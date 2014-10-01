from __future__ import print_function, absolute_import

import json


def all_subclasses(cls):
    return cls.__subclasses__() + [g for s in cls.__subclasses__() for g in all_subclasses(s)]


class Message(object):

    __cmd__ = None
    __mandatory_params__ = tuple()
    __optional_params__ = dict()

    @classmethod
    def from_str(cls, s):
        data = json.loads(s)

        result = []
        for cmd, params in data.items():
            message = cls.from_data(cmd, params)
            if message is not None:
                result.append(message)

        if len(result) == 1:
            return result[0]
        else:
            return result

    @classmethod
    def from_data(cls, cmd, params):
        message_cls = cls.find(cmd)
        if not message_cls:
            return None

        return message_cls(**params)

    @classmethod
    def all(cls):
        return all_subclasses(cls)

    @classmethod
    def find(cls, cmd):
        subclasses = cls.all()
        for subclass in subclasses:
            if hasattr(subclass, "__cmd__") and subclass.__cmd__ == cmd:
                return subclass
        return None

    def __init__(self, **kwargs):
        unseen_mandatory_params = list(self.__class__.__mandatory_params__)

        # set all optional params to their default values
        for k, v in self.__class__.__optional_params__.items():
            setattr(self, k, v)

        # now let's see what we got as constructor parameters
        for k, v in kwargs.items():
            # None values get skipped
            if v is None:
                continue

            # mandatory params get tracked
            elif k in self.__class__.__mandatory_params__:
                setattr(self, k, v)
                if k in unseen_mandatory_params:
                    unseen_mandatory_params.remove(k)

            # optional params get overwritten with the supplied value
            elif k in self.__class__.__optional_params__ and v:
                setattr(self, k, v)

        # not all mandatory params present? raise exception
        if len(unseen_mandatory_params) > 0:
            raise ValueError("Missing mandatory parameters: %r" % unseen_mandatory_params)

    def __str__(self):
        return json.dumps(self.__class__.to_message_obj(self), encoding="utf8", separators=(",", ":"))

    def __repr__(self):
        return "{name}({attrs})".format(name=self.__class__.__name__, attrs=repr(vars(self)))

    def send(self, io):
        json.dump(self.__class__.to_message_obj(self), io, encoding="utf8", separators=(",", ":"))

    @property
    def cmd(self):
        return self.__class__.__cmd__

    @classmethod
    def to_message_obj(cls, message):
        if not hasattr(message.__class__, "__cmd__") or message.__class__.__cmd__ is None:
            return None

        obj = dict()
        obj[message.__class__.__cmd__] = vars(message)
        return obj


class StartApMessage(Message):
    __cmd__ = "start_ap"


class StopApMessage(Message):
    __cmd__ = "stop_ap"


class ListWifiMessage(Message):
    __cmd__ = "list_wifi"
    __optional_params__ = dict(force=False)


class ConfigureWifiMessage(Message):
    __cmd__ = "config_wifi"
    __mandatory_params__ = ("ssid",)
    __optional_params__ = dict(psk=None, options=None, force=False)


class SelectWifiMessage(Message):
    __cmd__ = "start_wifi"


class StatusMessage(Message):
    __cmd__ = "status"


class ForgetWifiMessage(Message):
    __cmd__ = "forget_wifi"


class ResetMessage(Message):
    __cmd__ = "reset"


class Response(object):

    def __str__(self):
        return json.dumps(vars(self), encoding="utf8", separators=(",", ":"))

    def send(self, io):
        json.dump(vars(self), io, encoding="utf8", separators=(",", ":"))

    @property
    def content(self):
        return None

    @classmethod
    def from_str(cls, s):
        data = json.loads(s)

        result = []
        for cmd, params in data.items():
            response = cls.from_data(cmd, params)
            if response is not None:
                result.append(response)

        if len(result) == 1:
            return result[0]
        else:
            return result

    @classmethod
    def from_data(cls, type, result):
        if type == "result":
            return SuccessResponse(result)
        elif type == "error":
            return ErrorResponse(result)
        else:
            return None


class SuccessResponse(Response):

    def __init__(self, result):
        self.result = result

    @property
    def content(self):
        return self.result


class ErrorResponse(Response):

    def __init__(self, result):
        self.error = result

    @property
    def content(self):
        return self.error
