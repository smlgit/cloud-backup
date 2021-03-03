

def _construct_error_info(response_object, ignore_codes):
    """

    :param response_object:
    :param ignore_codes:
    :return: {'error_code': , 'reason' , 'message': } dict
    """
    result = {'error_code': None, 'reason': '', 'message': ''}

    if (response_object.status_code < 200 or response_object.status_code > 299 and
            response_object.status_code not in ignore_codes):
        try:
            rx_dict = response_object.json()
            print(rx_dict)

            if 'error' in rx_dict and 'code' in rx_dict['error']:
                result['error_code'] = rx_dict['error']['code']
                result['reason'] = rx_dict['error']['errors'][0]['reason']
            else:
                result['error_code'] = response_object.status_code

            if 'message' in rx_dict:
                result['message'] = rx_dict['message']
            elif 'error_description' in rx_dict:
                result['message'] = rx_dict['error_description']

        except:
            pass

    return result


def process_google_response_for_errors(response_object, logger, raise_for_status=True,
                                       ignore_codes=[]):
    """
    Will check for errors that require a backoff and return True if backoff is required.
    Will check for non-success codes and output any error messages in the log.
    Will raise exceptions for non success conditions if requested.

    :param response_object:
    :param logger:
    :param raise_for_status: if True, will raise any exception (other than those
    caused by codes in ignore_codes).
    :param ignore_codes: a list of http response codes that will be treated as
    successes.
    :return: True if backoff is required. False otherwise.
    """

    error_dict = _construct_error_info(response_object, ignore_codes)

    if error_dict['error_code'] is not None:
        if ((error_dict['error_code'] > 499 and error_dict['error_code'] < 600) or
                (error_dict['error_code'] == 429 and error_dict['reason'] == 'rateLimitExceeded')):
            # Try exponential backoff
            logger.warning('Google requested backoff with code {}, {}'.format(
                error_dict['error_code'], error_dict['message']
            ))
            return True

        logger.error('Google responded with error code: {}, message: {}'.format(
            error_dict['error_code'], error_dict['message']))

        if raise_for_status is True:
            response_object.raise_for_status()

    return False
