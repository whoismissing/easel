/* hello world in r_egg */
/* ragg2 -O -F hello.r */
write@syscall(1); //x64 write@syscall(1);
exit@syscall(60); //x64 exit@syscall(60);

main@global(128) {
  .var0 = "hello world!\n";
  write(1, .var0, 13);
  exit(0);
}
