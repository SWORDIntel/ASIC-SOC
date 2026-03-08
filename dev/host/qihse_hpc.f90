module qihse_hpc_module
    use iso_c_binding
    implicit none

contains

    ! L5 Hebbian Update
    subroutine qihse_hebbian_update_fortran(db, q, b, lr, vector_dims) bind(c, name="qihse_hebbian_update_fortran")
        integer(c_int), value :: b
        real(c_float), value :: lr
        integer(c_int), value :: vector_dims
        real(c_float), dimension(vector_dims, *), intent(inout) :: db
        real(c_float), dimension(vector_dims), intent(in) :: q

        ! Fortran array syntax enables SIMD optimization
        ! b is 0-indexed in C, so we use b+1 for Fortran 1-based indexing
        db(:, b + 1) = db(:, b + 1) + lr * (q(:) - db(:, b + 1))
    end subroutine qihse_hebbian_update_fortran

    ! L6 Correlation Finalizer
    subroutine me_correlation_finalizer_fortran(sum_x, sum_xy, sum_x2, final_scores, n_total, num_hypotheses) bind(c, name="me_correlation_finalizer_fortran")
        integer(c_int), value :: num_hypotheses
        real(c_float), value :: n_total
        real(c_float), dimension(num_hypotheses), intent(in) :: sum_x
        real(c_float), dimension(num_hypotheses), intent(in) :: sum_xy
        real(c_float), dimension(num_hypotheses), intent(in) :: sum_x2
        real(c_float), dimension(num_hypotheses), intent(out) :: final_scores

        real(c_float) :: sy, sy2
        real(c_float), dimension(num_hypotheses) :: num, den

        sy = n_total / 2.0
        sy2 = n_total / 2.0

        ! SIMD-ready array operations
        num = (n_total * sum_xy) - (sum_x * sy)
        den = sqrt(max(0.0, (n_total * sum_x2 - (sum_x**2)) * (n_total * sy2 - (sy**2))))

        where (den /= 0.0)
            final_scores = abs(num / den)
        elsewhere
            final_scores = 0.0
        end where
    end subroutine me_correlation_finalizer_fortran

end module qihse_hpc_module
