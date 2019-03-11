import os
import json
import logging
import time
import boto3
import urllib2
import urllib
import math
from botocore.vendored import requests
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ssmc = boto3.client('ssm')
glob_auth0_mgmt_token = None

intercom_headers = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'Authorization': 'Bearer %s' % (os.getenv('INTERCOM_ACCESS_TOKEN'))
  }


def get_ssm_param(key):
  resp = ssmc.get_parameter(
    Name=key,
    WithDecryption=True
  )
  return resp['Parameter']['Value']

discourse_api_key = get_ssm_param('com.neo4j.devrel.discourse.apikey')

def get_auth0_management_clientinfo():
  clientId = get_ssm_param('com.neo4j.accounts.prod.clientid')
  clientSecret = get_ssm_param('com.neo4j.accounts.prod.clientsecret')
  audience = get_ssm_param('com.neo4j.accounts.prod.audience')
  tokenEndpoint = get_ssm_param('com.neo4j.accounts.prod.tokenendpoint')
  apiEndpoint = get_ssm_param('com.neo4j.accounts.prod.apiendpoint')
  authci = {'client_id': clientId,
             'client_secret': clientSecret,
             'audience': audience,
             'token_endpoint': tokenEndpoint,
             'api_endpoint': apiEndpoint}
  return authci

def get_auth0_management_token():
  global glob_auth0_mgmt_token

  # if we have a stored token, and it doesn't expire in the next
  # 2 minutes, return it instead of getting new one
  if (glob_auth0_mgmt_token and
       ('expires' in glob_auth0_mgmt_token) and
       (time.time() + 120) < glob_auth0_mgmt_token['expires']):
    return glob_auth0_mgmt_token

  authci = get_auth0_management_clientinfo()
  clientSecret = authci['client_secret']
  clientId = authci['client_id']
  audience = authci['audience']
  tokenEndpoint = authci['token_endpoint']
  apiEndpoint = authci['api_endpoint']


  payload_obj = {
    "grant_type": "client_credentials",
    "client_id": clientId,
    "client_secret": clientSecret,
    "audience": audience
  }
  req = urllib2.Request(
            url = tokenEndpoint,
            headers = {"Content-type": "application/json"},
            data = json.dumps(payload_obj))

  f = urllib2.urlopen(url = req)
  data = f.read()
  data_obj = json.loads(data.decode("utf-8"))
  # subtract 2 seconds from expires to be safe due to delay between issue
  # and this code processing
  return_obj = {
    "access_token": data_obj["access_token"],
    "expires": data_obj["expires_in"] + math.floor(time.time()) - 2,
    "api_endpoint": apiEndpoint
  }
  glob_auth0_mgmt_token = return_obj
  return glob_auth0_mgmt_token

def get_auth0_user(userid):
  headers = {'Authorization': 'Bearer %s' % (get_auth0_management_token()['access_token'])}
  url = 'https://neo4j-sync.auth0.com/api/v2/users/%s' % (urllib.quote(userid))
  r = requests.get(url, headers=headers)
  user = r.json()
  return user

def set_auth0_user_verified(userid):
  headers = {'Authorization': 'Bearer %s' % (get_auth0_management_token()['access_token'])}
  url = 'https://neo4j-sync.auth0.com/api/v2/users/%s' % (urllib.quote(userid))
  r2 = requests.patch(url, json={'email_verified': True}, headers=headers)
  logger.info('Updating verified for: %s as %s' % (userid, r2.status_code))
  logger.info('Received response from settng email verified')
  logger.info(r2.text)

def get_external_id(username):
  r = requests.get('https://community.neo4j.com/users/%s.json?api_key=%s' % (username, discourse_api_key))
  json_response = json.loads(r.content)
  logger.debug('Received /users/(username).json response for username: %s' % (username))
  logger.debug(json_response)
  user_id = json_response['user']['id']
  logger.info('Found ID for username "%s" as: %s' % (username, user_id))

  r2 = requests.get('https://community.neo4j.com/admin/users/%s.json?api_key=%s' % (user_id, discourse_api_key))
  json_response = json.loads(r2.content)
  external_id = json_response['single_sign_on_record']['external_id']
  logger.info('Found external_id for user_id %s as: %s' % (user_id, external_id))
  return external_id

def get_admin_user_profile(user_id):
  logger.debug('Fetching https://community.neo4j.com/admin/users/%s.json?api_key=%s' % (user_id, discourse_api_key))
  r2 = requests.get('https://community.neo4j.com/admin/users/%s.json?api_key=%s' % (user_id, discourse_api_key))
  logger.info('Received response with status code: %s' % (r2.status_code))
  json_response = r2.json()
  external_id = json_response['single_sign_on_record']['external_id']
  logger.info('Found external_id for user_id %s as: %s' % (user_id, external_id))
  return json_response

def post_event(event, context):
  logger.info(json.dumps(event))
  logger.info(event['body'])
  dc_post_event = json.loads(event['body'])
  headers = event['headers']

  intercom_event_name = 'community-site-event'
  if ('X-Discourse-Event' in headers):
    intercom_event_name = 'community-site-%s' % (headers['X-Discourse-Event'])
    logger.info("Event name: " + headers['X-Discourse-Event'])

  if 'post' in dc_post_event:
    username = dc_post_event['post']['username']
    url = 'https://community.neo4j.com/t/%s/%s/%s' % (dc_post_event['post']['topic_slug'], dc_post_event['post']['topic_id'], dc_post_event['post']['post_number'])
    topic = dc_post_event['post']['topic_title']
  elif 'topic' in dc_post_event:
    username = dc_post_event['topic']['created_by']['username']
    url = 'https://community.neo4j.com/t/%s/%s' % (dc_post_event['topic']['slug'], dc_post_event['topic']['id'])
    topic = dc_post_event['topic']['title']
  else:
    username = None

  # POST INTERCOM EVENT
  payload = {
    'user_id': get_external_id(username),
    'created_at': int(time.time()),
    'event_name': intercom_event_name,
    'metadata': {
       'url': url,
       'topic': topic
     }
  }
  r = requests.post('https://api.intercom.io/events', data=json.dumps(payload), headers=intercom_headers)
  if r.status_code == 202:
    logger.info("Event sent to intercom successfully")
  else: 
    logger.error("Intercom event failure: %s" % (str(r.status_code)))
    logger.error(r.content)

  body = {
      "message": "Post event handled - sent to Intercom.",
      "input": event
  }

  response = {
      "statusCode": 200,
      "body": json.dumps(body)
  }
  return response


def user_event(event, context):
    body = {
        "message": "User event handled - sent to Intercom.",
        "input": event
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    logger.info(json.dumps(event))
    logger.info(event['body'])
    dc_user_event = json.loads(event['body'])
    dc_user = dc_user_event['user']
    headers = event['headers']
    dc_posts_created = 0
    dc_topics_created = 0

    intercom_event_name = 'community-site-event'
    if ('X-Discourse-Event' in headers):
      intercom_event_name = 'community-site-%s' % (headers['X-Discourse-Event'])
      logger.info("Event name: " + headers['X-Discourse-Event'])

    if 'external_id' in dc_user:
      admin_profile = get_admin_user_profile(dc_user['id'])
      if 'active' in admin_profile and admin_profile['active']:
        logger.info('User %s is active in discourse' % (dc_user['external_id']))
        # check if active in auth0
        logger.info('Getting auth0 user %s' % (dc_user['external_id']))
        auth0_profile = get_auth0_user(dc_user['external_id'])
        if 'email_verified' in auth0_profile and not auth0_profile['email_verified']:
          logger.info('Setting auth0 user %s as verified' % (dc_user['external_id']))
          set_auth0_user_verified(dc_user['external_id'])
        else:
          logger.info('Email already verified in auth0')

    # POST INTERCOM EVENT
    payload = {
      'user_id': dc_user['external_id'],
      'created_at': int(time.time()),
      'event_name': intercom_event_name,
      'metadata': {}
    }
    r = requests.post('https://api.intercom.io/events', data=json.dumps(payload), headers=intercom_headers)
    if r.status_code == 202:
      logger.info("Event sent to intercom successfully")
    else: 
      logger.error("Intercom event failure: %s" % (str(r.status_code)))
      logger.error(r.content)

    # POST INTERCOM USER INFO - STATS
    for stat in dc_user['stats']:
      if stat['action_type'] == 4:
          dc_topics_created = stat['count']
      elif stat['action_type'] == 5:
          dc_posts_created = stat['count']
    
    logger.info("Stats dc_posts_created: %s" % (dc_posts_created))
    logger.info("Stats dc_topics_created: %s" % (dc_topics_created))

    payload = {
      'user_id': dc_user['external_id'],
      'custom_attributes': {
        'discourse_posts_created': dc_posts_created,
        'discourse_topics_created': dc_topics_created
      }
    }
    r2 = requests.post('https://api.intercom.io/users', data=json.dumps(payload), headers=intercom_headers)
    if r2.status_code == 200:
      logger.info("Updated intercom successfully")
    else: 
      logger.error("Intercom update failure: %s" % (str(r2.status_code)))
      logger.info("Intercom update failure: %s" % (str(r2.content)))

    return response
