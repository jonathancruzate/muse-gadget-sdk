import asyncio
import uuid

from winrt.windows.devices.bluetooth.advertisement import (
    BluetoothLEAdvertisement,
    BluetoothLEAdvertisementPublisher,
    BluetoothLEManufacturerData,
)
from winrt.windows.storage.streams import DataWriter

SERVICE_UUID = "7fdd3d1c-38ea-46cf-8b46-314ecf5f240c"
NAME = "MuseGadget-3855D8"


def buf(data: bytes):
    w = DataWriter()
    if data:
        w.write_bytes(data)
    return w.detach_buffer()


async def trial(label: str, adv: BluetoothLEAdvertisement, extended: bool) -> None:
    pub = BluetoothLEAdvertisementPublisher(adv)
    try:
        pub.use_extended_advertisement = extended
    except Exception as exc:  # noqa: BLE001
        print(f"{label:44s} SET EXT RAISED: {exc!r}")
        return
    try:
        pub.start()
    except Exception as exc:  # noqa: BLE001
        print(f"{label:44s} START RAISED: {exc!r}")
        return
    await asyncio.sleep(2.0)
    print(f"{label:44s} status={pub.status}")
    try:
        pub.stop()
    except Exception:  # noqa: BLE001
        pass
    await asyncio.sleep(0.3)


def full_adv() -> BluetoothLEAdvertisement:
    adv = BluetoothLEAdvertisement()
    adv.local_name = NAME
    adv.service_uuids.append(uuid.UUID(SERVICE_UUID))
    adv.manufacturer_data.append(BluetoothLEManufacturerData(0xFFFF, buf(b"\x00")))
    return adv


def name_adv() -> BluetoothLEAdvertisement:
    adv = BluetoothLEAdvertisement()
    adv.local_name = NAME
    adv.manufacturer_data.append(BluetoothLEManufacturerData(0xFFFF, buf(b"\x00")))
    return adv


async def main() -> None:
    await trial("extended: name+uuid+mfr", full_adv(), True)
    await trial("extended: name+mfr", name_adv(), True)


asyncio.run(main())
print("PROBE_EXT_DONE")
