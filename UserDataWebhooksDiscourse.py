import os
import json
import logging
import time
from botocore.vendored import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

intercom_headers = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'Authorization': 'Bearer %s' % (os.getenv('INTERCOM_ACCESS_TOKEN'))
  }

discourse_api_key = os.getenv('DISCOURSE_API_KEY')

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
      logger.info("User: " + dc_user['external_id'])

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
