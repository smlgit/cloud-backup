from providers.google.drive import GoogleDrive, GoogleServerData
from providers.microsoft.drive import OneDrive, MicrosoftServerData


_implementations = {
    'google': {'drive': GoogleDrive},
    'microsoft': {'drive': OneDrive}
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