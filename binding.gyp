{
  "targets": [
    {
      "target_name": "tokamak",
      "sources": [ "src/tinysocket.cc", "src/tokamak.cc" ]
    }
  ],
  "cflags": [
    "-O3",
    "-std=c99",
    "-D_GNU_SOURCE"
  ]
}