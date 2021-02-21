from providers.google.drive import GoogleDrive, GoogleServerData


_implementations = {
    'google': {'drive': GoogleDrive}
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