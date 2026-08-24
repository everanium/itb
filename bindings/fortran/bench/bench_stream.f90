! Stream-pump encrypt throughput vs plaintext size at
! 1 MiB / 16 MiB / 64 MiB.

program bench_stream
  use, intrinsic :: iso_c_binding, only: c_int64_t, c_int
  use, intrinsic :: iso_fortran_env, only: error_unit, int64, real64
  use itb
  use bench_common
  implicit none

  integer, parameter :: sizes(3) = [2**20, 16 * 2**20, 64 * 2**20]

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: pipe
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:)
  integer(c_int64_t) :: prev_limit
  integer(c_int)     :: prev_gc
  integer :: i

  ! Bench-scale allocation churn leaks Go scratch heap unboundedly
  ! without a soft memory cap + aggressive GC; the return values
  ! report the previous settings, not an error.
  prev_limit = itb_set_memory_limit(int(512, c_int64_t) * 1024 * 1024)
  prev_gc = itb_set_gc_percent(20_c_int)

  call bench_build_opts(opts)
  call itb_pipeline_init(pipe, &
      bench_profile_name("streaming-noaead-triple-v1"), opts, err)
  if (.not. itb_ok(err)) then
    write (error_unit, '(a)') "bench_stream: init failed: "// &
        itb_error_text(err)
    error stop 1
  end if

  call bench_header()
  do i = 1, size(sizes)
    allocate (plain(sizes(i)))
    call csprng_fill(plain)
    call run_case(sizes(i))
    deallocate (plain)
  end do
  call itb_pipeline_free(pipe)

contains

  ! One untimed warm-up, then iterate until the wall-clock budget
  ! and iteration floor are both met.
  subroutine run_case(size_bytes)
    integer, intent(in) :: size_bytes
    real(real64) :: start, elapsed, budget
    integer(int64) :: iters
    logical :: ok

    call run_stream_pump(ok)
    if (.not. ok) then
      write (error_unit, '(a)') "bench_stream: warm-up failed"
      error stop 1
    end if
    start = bench_now()
    elapsed = 0.0_real64
    iters = 0_int64
    budget = bench_min_seconds()
    do while (elapsed < budget .or. iters < BENCH_MIN_ITERS)
      call run_stream_pump(ok)
      if (.not. ok) then
        write (error_unit, '(a)') "bench_stream: iteration failed"
        error stop 1
      end if
      iters = iters + 1
      elapsed = bench_now() - start
    end do
    call bench_report("stream_pump", size_bytes, iters, elapsed)
  end subroutine

  subroutine run_stream_pump(ok)
    logical, intent(out) :: ok
    integer(c_int8_t), allocatable :: wire(:)
    type(itb_error_t) :: run_err

    call itb_encrypt_stream_pump(pipe, plain, wire, run_err)
    ok = itb_ok(run_err)
  end subroutine

end program
