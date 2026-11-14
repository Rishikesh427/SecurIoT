"""Bounded Gemini JSON transport; credentials remain server-side."""
import json
import os
import urllib.parse
import urllib.request


def configured():
    return all(value and not value.startswith('PASTE_') for value in
               (os.getenv('GEMINI_API_KEY', '').strip(), os.getenv('GEMINI_MODEL', '').strip()))


def generate(system, payload, schema, *, timeout=6):
    if not configured():
        raise ValueError('Gemini is not configured')
    model = urllib.parse.quote(os.environ['GEMINI_MODEL'].strip(), safe='-._')
    body = {'systemInstruction': {'parts': [{'text': system}]},
            'contents': [{'role': 'user', 'parts': [{'text': json.dumps(payload)}]}],
            'generationConfig': {'responseMimeType': 'application/json', 'responseJsonSchema': schema,
                                 'temperature': .2, 'maxOutputTokens': 2048}}
    request = urllib.request.Request(
        f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
        json.dumps(body).encode(), {'Content-Type': 'application/json',
                                   'x-goog-api-key': os.environ['GEMINI_API_KEY'].strip()})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError('Gemini response too large')
    candidate = json.loads(raw)['candidates'][0]
    if candidate.get('finishReason') != 'STOP':
        raise ValueError('Incomplete or blocked response')
    text = ''.join(p.get('text', '') for p in candidate['content']['parts'] if not p.get('thought'))
    return json.loads(text)
