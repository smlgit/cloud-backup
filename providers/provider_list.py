from providers.google.drive import GoogleDrive, GoogleServerData
from providers.microsoft.drive import OneDrive, MicrosoftServerData
from providers.pcloud.drive import PcloudDrive, PcloudServerData
from providers.yandex.drive import YandexDrive, YandexServerData
from providers.box.drive import BoxDrive, BoxServerData


_implementations = {
    'google': {'drive': GoogleDrive},
    'microsoft': {'drive': OneDrive},
    'pcloud': {'drive': PcloudDrive},
    'yandex': {'drive': YandexDrive},
    'box': {'drive': BoxDrive},
}


def get_supported_provider_names():
    return [key for key in _implementations.keys()]


def get_drive_class(provider_name):
    if provider_name in _implementations:
        return _implementations[provider_name]['drive']

    raise ValueError('The provider {} is not supported.'.format(provider_name))


def init_providers():
    """
    Just sets up provider metadata for general operation.
    :return: None
    """
    GoogleServerData.set_to_google_server()
    MicrosoftServerData.set_to_microsoft_server()
    PcloudServerData.set_to_pcloud_server()
    YandexServerData.set_to_yandex_server()
    BoxServerData.set_to_box_server()