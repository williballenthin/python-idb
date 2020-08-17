#!/usr/bin/env python
"""
Parse and display license information from an IDA Pro database.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import argparse
import datetime
import logging
import struct
import sys
import binascii

from vstruct.primitives import v_zstr_utf8

import idb
import idb.netnode

logger = logging.getLogger(__name__)


def is_encrypted(buf):
    return buf.find(b"\x00" * 4) >= 0x7F


HEXRAYS_PUBKEY = 0x93AF7A8E3A6EB93D1B4D1FB7EC29299D2BC8F3CE5F84BFE88E47DDBDD5550C3CE3D2B16A2E2FBD0FBD919E8038BB05752EC92DD1498CB283AA087A93184F1DD9DD5D5DF7857322DFCD70890F814B58448071BBABB0FC8A7868B62EB29CC2664C8FE61DFBC5DB0EE8BF6ECF0B65250514576C4384582211896E5478F95C42FDED


def decrypt(buf):
    """
    decrypt the given 1024-bit blob using Hex-Ray's public key.

    i'm not sure from where this public key originally came.
    the algorithm is derived from here:
        https://github.com/nlitsme/pyidbutil/blob/87cb3235a462774eedfafca00f67c3ce01eeb326/idbtool.py#L43

    Args:
      buf (bytes): at least 0x80 bytes, of which the first 1024 bits will be decrypted.

    Returns:
      bytes: 0x80 bytes of decrypted data.
    """
    enc = int(binascii.hexlify(buf[127::-1]), 16)
    dec = pow(enc, 0x13, HEXRAYS_PUBKEY)
    return binascii.a2b_hex("%0256x" % dec)


def parse_user_data(buf):
    """
    parse a decrypted user blob into a structured dictionary.

    Args:
      buf (bytes): exactly 0x80 bytes of plaintext data.

    Returns:
      Dict[str, Any]: a dictionary with the following values:
        - ts1 (datetime.datetime): timestamp in UTC of something. database creation?
        - ts2 (datetime.datetime): timestamp in UTC of something. sometimes zero.
        - id (str): the ID of the license.
        - name (str): the name of the user and organization that owns the license.
    """
    if len(buf) != 0x7F:
        raise ValueError("invalid user blob.")

    version = struct.unpack_from("<H", buf, 0x2)[0]
    if version == 0 or version > 750:
        raise NotImplementedError("user blob version not supported.")

    ts1, _, ts2 = struct.unpack_from("<III", buf, 0x10)
    id = "%02X-%02X%02X-%02X%02X-%02X" % struct.unpack_from("6B", buf, 0x1C)

    name = v_zstr_utf8()
    name.vsParse(buf[0x22:])

    return {
        # unknown if these are in UTC or not. right now, assuming so.
        "ts1": datetime.datetime.utcfromtimestamp(ts1),
        "ts2": datetime.datetime.utcfromtimestamp(ts2),
        "id": id,
        "name": name,
    }


def get_userdata(netnode):
    """
    fetch, decrypt, and parse the user data from the given netnode.

    Args:
      netnode (ida_netnode.Netnode): the netnode containing the user data.

    Returns:
      dict[str, Any]: see `parse_user_data`.
    """
    userdata = netnode.supval(0x0)

    if is_encrypted(userdata):
        userdata = decrypt(userdata)[1:]
    else:
        userdata = userdata[:0x7F]

    return parse_user_data(userdata)


def print_userdata(api, tag="$ original user"):
    try:
        netnode = api.ida_netnode.netnode(tag)
        data = get_userdata(netnode)
        print("user: %s" % data["name"])
        print("id:   %s" % data["id"])
        print("ts1:  %s" % data["ts1"].isoformat(" ") + "Z")
        print("ts2:  %s" % data["ts2"].isoformat(" ") + "Z")
    except KeyError:
        logger.warning("can' find {}".format(tag))
    except (NotImplementedError, ValueError) as e:
        logger.warning(e)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Parse and display license information from an IDA Pro database."
    )
    parser.add_argument("idbpath", type=str, help="Path to input idb file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Disable all output but errors"
    )
    args = parser.parse_args(args=argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    with idb.from_file(args.idbpath) as db:
        api = idb.IDAPython(db)
        print_userdata(api)
        print_userdata(api, "$ user1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
