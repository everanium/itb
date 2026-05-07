! itb_cipher.f90 -- low-level free-function cipher entry points.
!
! Mirrors the C binding's `itb_encrypt` / `itb_decrypt` /
! `itb_encrypt_auth` / `itb_decrypt_auth` (Single Ouroboros, 3-seed)
! plus their Triple Ouroboros (7-seed) counterparts.
!
! Probe-then-call path: each function makes a discover-call against
! libitb with a NULL output pointer and zero capacity. libitb refuses
! to write and returns `STATUS_BUFFER_TOO_SMALL`, but it sets the
! out-length parameter to the exact number of bytes the result would
! occupy. The wrapper allocates a result array of that exact size and
! issues a second real call that writes into the buffer. There is no
! over-allocation, no scratch buffer, and no truncation step --
! libitb dictates the precise output size up front, so the result
! array is sized correctly the first time it is allocated. Empty
! input plaintext / ciphertext is NOT accepted by libitb -- the call
! returns `STATUS_ENCRYPT_FAILED` and the wrapper raises via
! error stop.
!
! Threading: the free-function cipher entry points ARE thread-safe
! when each concurrent invocation uses distinct seed handles and a
! distinct MAC handle (where applicable). Process-wide setters
! (`itb_set_bit_soup` / `itb_set_lock_soup` / `itb_set_max_workers`
! / `itb_set_nonce_bits` / `itb_set_barrier_fill`) snapshot at call
! entry; mutating any of them mid-cipher corrupts the running
! operation -- treat them as set-once-at-startup.

module itb_cipher
  use itb_kinds
  use itb_sys
  use itb_seed,   only: itb_seed_t
  use itb_mac,    only: itb_mac_t
  use itb_errors, only: STATUS_OK, STATUS_BUFFER_TOO_SMALL, raise_itb_error
  implicit none
  private

  public :: itb_encrypt
  public :: itb_decrypt
  public :: itb_encrypt_auth
  public :: itb_decrypt_auth

  public :: itb_encrypt_triple
  public :: itb_decrypt_triple
  public :: itb_encrypt_auth_triple
  public :: itb_decrypt_auth_triple

contains

  ! ----------------------------------------------------------------
  ! Single Ouroboros (3-seed)
  ! ----------------------------------------------------------------

  function itb_encrypt(noise, data, start, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    out_len = 0_itb_size_kind
    rc = itb_encrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                        in_ptr, ptlen, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (ciphertext(out_len))

    rc = itb_encrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                        in_ptr, ptlen, c_loc(ciphertext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

  function itb_decrypt(noise, data, start, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    out_len = 0_itb_size_kind
    rc = itb_decrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                        in_ptr, ctlen, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (plaintext(out_len))

    rc = itb_decrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                        in_ptr, ctlen, c_loc(plaintext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

  function itb_encrypt_auth(noise, data, start, mac, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    out_len = 0_itb_size_kind
    rc = itb_encrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                              mac%raw_handle(), in_ptr, ptlen, &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (ciphertext(out_len))

    rc = itb_encrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                              mac%raw_handle(), in_ptr, ptlen, &
                              c_loc(ciphertext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

  function itb_decrypt_auth(noise, data, start, mac, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    out_len = 0_itb_size_kind
    rc = itb_decrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                              mac%raw_handle(), in_ptr, ctlen, &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (plaintext(out_len))

    rc = itb_decrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                              mac%raw_handle(), in_ptr, ctlen, &
                              c_loc(plaintext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

  ! ----------------------------------------------------------------
  ! Triple Ouroboros (7-seed)
  ! ----------------------------------------------------------------

  function itb_encrypt_triple(noise, data1, data2, data3, &
                                start1, start2, start3, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    out_len = 0_itb_size_kind
    rc = itb_encrypt3_c(noise%raw_handle(),                              &
                         data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                         start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                         in_ptr, ptlen, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (ciphertext(out_len))

    rc = itb_encrypt3_c(noise%raw_handle(),                              &
                         data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                         start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                         in_ptr, ptlen, c_loc(ciphertext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

  function itb_decrypt_triple(noise, data1, data2, data3, &
                                start1, start2, start3, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    out_len = 0_itb_size_kind
    rc = itb_decrypt3_c(noise%raw_handle(),                              &
                         data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                         start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                         in_ptr, ctlen, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (plaintext(out_len))

    rc = itb_decrypt3_c(noise%raw_handle(),                              &
                         data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                         start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                         in_ptr, ctlen, c_loc(plaintext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

  function itb_encrypt_auth_triple(noise, data1, data2, data3, &
                                     start1, start2, start3, mac, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    out_len = 0_itb_size_kind
    rc = itb_encrypt_auth3_c(noise%raw_handle(),                              &
                              data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                              mac%raw_handle(),                                &
                              in_ptr, ptlen, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (ciphertext(out_len))

    rc = itb_encrypt_auth3_c(noise%raw_handle(),                              &
                              data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                              mac%raw_handle(),                                &
                              in_ptr, ptlen, c_loc(ciphertext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

  function itb_decrypt_auth_triple(noise, data1, data2, data3, &
                                     start1, start2, start3, mac, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    out_len = 0_itb_size_kind
    rc = itb_decrypt_auth3_c(noise%raw_handle(),                              &
                              data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                              mac%raw_handle(),                                &
                              in_ptr, ctlen, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    allocate (plaintext(out_len))

    rc = itb_decrypt_auth3_c(noise%raw_handle(),                              &
                              data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                              mac%raw_handle(),                                &
                              in_ptr, ctlen, c_loc(plaintext), out_len, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end function

end module itb_cipher
