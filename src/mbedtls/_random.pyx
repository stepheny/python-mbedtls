"""Random number generator (RNG) wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free
cimport mbedtls._random as random
import binascii
from mbedtls.exceptions import check_error


cdef class Entropy:

    def __cinit__(self):
        """Initialize the context."""
        random.mbedtls_entropy_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        random.mbedtls_entropy_free(&self._ctx)

    def gather(self):
        """Trigger an extra gather poll for the accumulator."""
        random.mbedtls_entropy_gather(&self._ctx)

    def retrieve(self, size_t length):
        """Retrieve entropy from the accumulator."""
        cdef unsigned char* output = <unsigned char*>malloc(
            length * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(random.mbedtls_entropy_func(
                &self._ctx, output, length))
            return bytes(output[:length])
        finally:
            free(output)

    def update(self, const unsigned char[:] data):
        """Add data to the accumulator manually."""
        check_error(random.mbedtls_entropy_update_manual(
            &self._ctx, &data[0], data.shape[0]))


cdef class Random:

    def __cinit__(self):
        """Initialize the context."""
        random.mbedtls_ctr_drbg_init(&self._ctx)
        self._entropy = Entropy()
        check_error(random.mbedtls_ctr_drbg_seed(
            &self._ctx,
            &random.mbedtls_entropy_func, &self._entropy._ctx,
            NULL, 0))

    def __dealloc__(self):
        """Free and clear the context."""
        random.mbedtls_ctr_drbg_free(&self._ctx)

    def reseed(self):
        """Reseed the RNG."""
        check_error(random.mbedtls_ctr_drbg_reseed(&self._ctx, NULL, 0))

    def update(self, const unsigned char[:] data):
        """Update state with additional data."""
        random.mbedtls_ctr_drbg_update(&self._ctx, &data[0], data.shape[0])

    def token_bytes(self, size_t length):
        """Returns `length` random bytes."""
        cdef unsigned char* output = <unsigned char*>malloc(
            length * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(random.mbedtls_ctr_drbg_random(
                &self._ctx, output, length))
            return bytes(output[:length])
        finally:
            free(output)

    def token_hex(self, length):
        """Same as `token_bytes` but returned as a string."""
        return binascii.hexlify(self.token_bytes(length)).decode("ascii")
