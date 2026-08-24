! itb_stream.f90 -- incremental stream sessions over an open Pipeline.
!
! A session is a dumb byte pump: an encrypt session takes plaintext
! in through itb_stream_write and yields wire through itb_stream_read
! / itb_stream_drain_all; a decrypt session is the mirror (wire in,
! plaintext out). All chunking, MAC, envelope, and wire-format
! decisions stay inside libitb.
!
! Lifetime discipline: every successful itb_encrypt_stream_begin /
! itb_decrypt_stream_begin must be paired with exactly one
! itb_stream_free call, which cancels (if still running) and releases
! the session from any state. A session must not outlive its parent
! Pipeline.
!
! The whole-buffer pumps (itb_encrypt_stream_pump /
! itb_decrypt_stream_pump) feed 1 MiB slices and drain between
! writes so the Go-side spool stays bounded.

module itb_stream
  use, intrinsic :: iso_c_binding, only: c_int, c_int8_t, c_size_t, &
      c_intptr_t, c_ptr, c_loc, c_null_ptr
  use itb_status
  use itb_ffi
  use itb_error
  use itb_pipeline
  implicit none
  private

  public :: itb_stream_t
  public :: itb_encrypt_stream_begin, itb_decrypt_stream_begin
  public :: itb_stream_write, itb_stream_end, itb_stream_read
  public :: itb_stream_drain_all, itb_stream_free
  public :: itb_encrypt_stream_pump, itb_decrypt_stream_pump

  type :: itb_stream_t
    integer(c_intptr_t) :: handle = 0_c_intptr_t
    logical             :: ended = .false.
  end type

  ! Feed / drain slice size used by the pump loops.
  integer, parameter :: PUMP_BUF = 2**20

contains

  ! Opens an incremental encrypt session (plaintext in, wire out).
  subroutine itb_encrypt_stream_begin(pipe, sess, err)
    type(itb_pipeline_t), intent(in) :: pipe
    type(itb_stream_t), intent(out)  :: sess
    type(itb_error_t), intent(out)   :: err
    integer(c_intptr_t) :: handle

    call itb_error_set(err, &
        c_itb_triple_encrypt_stream_begin(pipe%handle, handle))
    if (itb_ok(err)) sess%handle = handle
  end subroutine

  ! Opens an incremental decrypt session (wire in, plaintext out).
  subroutine itb_decrypt_stream_begin(pipe, sess, err)
    type(itb_pipeline_t), intent(in) :: pipe
    type(itb_stream_t), intent(out)  :: sess
    type(itb_error_t), intent(out)   :: err
    integer(c_intptr_t) :: handle

    call itb_error_set(err, &
        c_itb_triple_decrypt_stream_begin(pipe%handle, handle))
    if (itb_ok(err)) sess%handle = handle
  end subroutine

  ! Feeds src into the session. Blocks until the cipher chain accepts
  ! the bytes; errors are sticky. A zero-length src is a no-op.
  subroutine itb_stream_write(sess, src, err)
    type(itb_stream_t), intent(inout)                 :: sess
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    type(itb_error_t), intent(out)                    :: err
    type(c_ptr) :: src_p

    src_p = c_null_ptr
    if (size(src) > 0) src_p = c_loc(src(1))
    call itb_error_set(err, c_itb_triple_stream_write(sess%handle, &
        src_p, size(src, kind=c_size_t)))
  end subroutine

  ! Signals end-of-input. Idempotent; itb_stream_write after end
  ! fails with ITB_STATUS_BAD_INPUT.
  subroutine itb_stream_end(sess, err)
    type(itb_stream_t), intent(inout) :: sess
    type(itb_error_t), intent(out)    :: err

    call itb_error_set(err, c_itb_triple_stream_end(sess%handle))
    if (itb_ok(err)) sess%ended = .true.
  end subroutine

  ! Drains up to size(buf) produced bytes into buf(1:n_read).
  ! finished becomes .true. once the session has ended AND the spool
  ! is fully drained. Partial drains are normal. Before end, an
  ! empty-spool read returns n_read = 0 without blocking; after end
  ! it blocks until the terminal bytes arrive or the session errors.
  subroutine itb_stream_read(sess, buf, n_read, finished, err)
    type(itb_stream_t), intent(inout)                    :: sess
    integer(c_int8_t), intent(inout), target, contiguous :: buf(:)
    integer, intent(out)                                 :: n_read
    logical, intent(out)                                 :: finished
    type(itb_error_t), intent(out)                       :: err
    integer(c_size_t) :: out_len
    integer(c_int)    :: fin

    n_read = 0
    finished = .false.
    out_len = 0_c_size_t
    fin = 0
    call itb_error_set(err, c_itb_triple_stream_read(sess%handle, &
        c_loc(buf(1)), size(buf, kind=c_size_t), out_len, fin))
    if (.not. itb_ok(err)) return
    n_read = int(out_len)
    finished = (fin /= 0)
  end subroutine

  ! Calls end (if not yet called) and appends every remaining output
  ! byte to dst (allocated / grown as needed).
  subroutine itb_stream_drain_all(sess, dst, err)
    type(itb_stream_t), intent(inout)             :: sess
    integer(c_int8_t), allocatable, intent(inout) :: dst(:)
    type(itb_error_t), intent(out)                :: err
    integer(c_int8_t), allocatable, target :: buf(:)
    integer :: n, used
    logical :: fin

    allocate (buf(PUMP_BUF))
    if (.not. allocated(dst)) allocate (dst(0))
    if (.not. sess%ended) then
      call itb_stream_end(sess, err)
      if (.not. itb_ok(err)) return
    end if
    used = size(dst)
    do
      call itb_stream_read(sess, buf, n, fin, err)
      if (.not. itb_ok(err)) return
      call append_bytes(dst, used, buf, n)
      if (fin) exit
    end do
    call trim_bytes(dst, used)
  end subroutine

  ! Cancels (if still running) and releases the session. Safe from
  ! any state; the status of the underlying free is deliberately
  ! discarded on this destructor path.
  subroutine itb_stream_free(sess)
    type(itb_stream_t), intent(inout) :: sess
    integer(c_int) :: rc

    if (sess%handle /= 0_c_intptr_t) then
      rc = c_itb_triple_stream_free(sess%handle)
      if (rc /= ITB_STATUS_OK) continue
    end if
    sess%handle = 0_c_intptr_t
    sess%ended = .false.
  end subroutine

  ! Pumps src through an encrypt session into dst with bounded
  ! Go-side spooling: feed a 1 MiB slice, drain available wire,
  ! repeat; end + final drain after the last slice. The session is
  ! freed on return (success or failure).
  subroutine itb_encrypt_stream_pump(pipe, src, dst, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    integer(c_int8_t), allocatable, intent(out)       :: dst(:)
    type(itb_error_t), intent(out)                    :: err

    call pump(pipe, .true., src, dst, err)
  end subroutine

  ! Receive-side counterpart of itb_encrypt_stream_pump.
  subroutine itb_decrypt_stream_pump(pipe, src, dst, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    integer(c_int8_t), allocatable, intent(out)       :: dst(:)
    type(itb_error_t), intent(out)                    :: err

    call pump(pipe, .false., src, dst, err)
  end subroutine

  subroutine pump(pipe, encrypt, src, dst, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    logical, intent(in)                               :: encrypt
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    integer(c_int8_t), allocatable, intent(out)       :: dst(:)
    type(itb_error_t), intent(out)                    :: err
    type(itb_stream_t)                     :: sess
    integer(c_int8_t), allocatable, target :: buf(:)
    integer :: lo, hi, n, used
    logical :: fin

    allocate (buf(PUMP_BUF))
    if (encrypt) then
      call itb_encrypt_stream_begin(pipe, sess, err)
    else
      call itb_decrypt_stream_begin(pipe, sess, err)
    end if
    if (.not. itb_ok(err)) return

    allocate (dst(0))
    used = 0
    lo = 1
    do while (lo <= size(src))
      hi = min(lo + PUMP_BUF - 1, size(src))
      call itb_stream_write(sess, src(lo:hi), err)
      if (.not. itb_ok(err)) then
        call itb_stream_free(sess)
        return
      end if
      lo = hi + 1
      ! Drain whatever the chain has produced so far; a read before
      ! end never blocks.
      do
        call itb_stream_read(sess, buf, n, fin, err)
        if (.not. itb_ok(err)) then
          call itb_stream_free(sess)
          return
        end if
        if (n == 0) exit
        call append_bytes(dst, used, buf, n)
      end do
    end do

    call itb_stream_end(sess, err)
    if (.not. itb_ok(err)) then
      call itb_stream_free(sess)
      return
    end if
    do
      call itb_stream_read(sess, buf, n, fin, err)
      if (.not. itb_ok(err)) then
        call itb_stream_free(sess)
        return
      end if
      call append_bytes(dst, used, buf, n)
      if (fin) exit
    end do
    call itb_stream_free(sess)
    call trim_bytes(dst, used)
  end subroutine

  ! Amortised append: dst holds `used` valid bytes and grows by
  ! doubling; the caller trims to the exact length at the end via
  ! trim_bytes.
  subroutine append_bytes(dst, used, src, n)
    integer(c_int8_t), allocatable, intent(inout) :: dst(:)
    integer, intent(inout)                        :: used
    integer(c_int8_t), intent(in)                 :: src(:)
    integer, intent(in)                           :: n
    integer(c_int8_t), allocatable :: grown(:)
    integer :: cap

    if (n <= 0) return
    cap = size(dst)
    if (used + n > cap) then
      cap = max(cap * 2, used + n, 65536)
      allocate (grown(cap))
      if (used > 0) grown(1:used) = dst(1:used)
      call move_alloc(grown, dst)
    end if
    dst(used + 1:used + n) = src(1:n)
    used = used + n
  end subroutine

  subroutine trim_bytes(dst, used)
    integer(c_int8_t), allocatable, intent(inout) :: dst(:)
    integer, intent(in)                           :: used
    integer(c_int8_t), allocatable :: exact(:)

    if (size(dst) == used) return
    allocate (exact(used))
    if (used > 0) exact(1:used) = dst(1:used)
    call move_alloc(exact, dst)
  end subroutine

end module itb_stream
