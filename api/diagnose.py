"""Read-only configuration checks; --gemini makes exactly one provider request."""
import argparse
import json
import os
from api.settings import environment
from ml.securiot_ml import advisor
from ml.securiot_ml.research import failure
from ml.securiot_ml.usage_guard import status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gemini', action='store_true')
    args = parser.parse_args()
    env = environment()
    for key in ('GEMINI_API_KEY', 'GEMINI_MODEL', 'GEMINI_STATE_PATH', 'GEMINI_DAILY_REQUEST_LIMIT'):
        if env.get(key): os.environ.setdefault(key, env[key])
    result = {'gemini_configured': advisor.configured(),
              'model': os.getenv('GEMINI_MODEL', ''),
              'agent_key_configured': bool(env.get('AGENT_API_KEY')),
              'database_url_present': bool(env.get('DATABASE_URL')), 'usage':status()}
    if args.gemini:
        if not advisor.configured(): result['provider_check'] = 'configuration_missing'
        else:
            try:
                answer = advisor._gemini('Reply with OK only.', {'request':'connection check'})
                result['provider_check'] = 'success' if answer else 'empty_response'
            except Exception as error:
                result['provider_check'] = failure(error)
    result["usage"] = status()
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
