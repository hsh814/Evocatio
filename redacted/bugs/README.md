# Bug reproducers

## GNU Binary Utilities

- CVE-2017-6965: [heap buffer overflow][sourceware-21137]

      guix shell binutils-with-asan@2.27
      readelf -w cve/2017/6965/bug_3

- CVE-2017-14745: [integer overflow][sourceware-22148]

      guix shell binutils@2.29
      objdump -d cve/2017/14745/crash_1

- CVE-2017-15020: [heap buffer overflow][sourceware-22202]

      guix shell binutils-with-asan@2.29
      nm -l cve/2017/15020/reproducer

- CVE-2017-15025: [division by zero][sourceware-22186]

      guix shell binutils@2.29
      nm -l cve/2017/15025/3899.crashes.bin
      nm -l cve/2017/15025/floatexception.elf
      objdump -S cve/2017/15025/floatexception.elf

- CVE-2018-10372: [heap buffer overflow][sourceware-23064]

      guix shell binutils-with-asan@2.30
      readelf -w cve/2018/10372/bug3

- CVE-2019-9077: [heap buffer overflow][sourceware-24243]

      guix shell binutils-with-asan@2.32
      readelf -a cve/2019/9077/hbo2

## GNU Core Utilities

- #19784: [heap buffer overflow][gnu-19784]

      guix shell coreutils-with-make-prime-list-with-asan@8.23
      make-prime-list 3  # or: $(xargs -0 -a gnu/19784/argv)

- #25003: [negative size param][gnu-25003]

      guix shell coreutils-with-asan@8.26-sans-4954f79
      split -n2/3 /dev/null  # or: $(xargs -0 -a gnu/25003/argv)

- #25023: [global buffer overflow][gnu-25023]

      guix shell coreutils-with-asan@8.25
      pr -m -S"$(printf '\t\t\t')" -t /dev/null /dev/zero

- #26545: [memcpy param overlap][gnu-26545]

      guix shell coreutils-with-asan@8.27
      shred -n4 -s7 /dev/null  # or: $(xargs -0 -a gnu/26545/argv)

## JasPer

- CVE-2016-8691: [divide-by-zero][jasper-22]

      guix shell jasper@1.900.3
      imginfo -f cve/2016/8691/11.crash

- CVE-2016-9387: [assertion failure][jasper-49]

      guix shell jasper@1.900.5
      imginfo -f cve/2016/9387/jas_matrix.jp2

- CVE-2016-9557: [signed integer overflow][jasper-67]

      guix shell jasper-with-ubsan@1.900.19
      imginfo -f cve/2016/9557/signed-int-overflow.jp2

## libarchive

- CVE-2016-5844: [signed integer overflow][libarchive-717]

      guix shell libarchive-with-ubsan@3.2.0
      bsdtar -tf cve/2016/5844/libarchive-signed-int-overflow.iso

## libjpeg-turbo

- CVE-2012-2806: [heap buffer overflow][chromium-40058947]

      guix shell libjpeg-turbo-with-asan@1.2.0
      djpeg cve/2012/2806/cnode0006-heap-buffer-overflow-796.jpg

- CVE-2017-15232: [null pointer dereference][mozjpeg-268]

      guix shell libjpeg-turbo@1.5.2
      djpeg -crop "1x1+16+16" -onepass -dither ordered -dct float -colors 8\
        -targa -grayscale -outfile /dev/null cve/2017/15232/1.jpg
      djpeg -crop "1x1+16+16" -onepass -dither ordered -dct float -colors 8\
        -targa -grayscale -outfile /dev/null cve/2017/15232/2.jpg

- CVE-2018-14498: [heap buffer overflow][libjpeg-turbo-258]

      guix shell libjpeg-turbo-with-asan@1.5.3
      cjpeg -outfile /dev/null cve/2018/14498/hbo_rdbmp.c:209_1.bmp
      cjpeg -outfile /dev/null cve/2018/14498/hbo_rdbmp.c:209_2.bmp
      cjpeg -outfile /dev/null cve/2018/14498/hbo_rdbmp.c:210_1.bmp
      cjpeg -outfile /dev/null cve/2018/14498/hbo_rdbmp.c:211_1.bmp
      cjpeg -outfile /dev/null cve/2018/14498/hbo_rdbmp.c:211_2.bmp

- CVE-2018-19664: [heap buffer overflow][libjpeg-turbo-305]

      guix shell libjpeg-turbo-with-asan@2.0.1
      djpeg -colors 256 -bmp cve/2018/19664/heap-buffer-overflow-2.jpg

## libming

- CVE-2016-9265: [division by zero][oss-sec-20161110-9]

      guix shell libming@0.4.7
      listmp3 cve/2016/9265/34.mp3
      listmp3 cve/2016/9265/45.mp3

- CVE-2018-8806: [use after free][libming-128]

      guix shell libming-with-asan@0.4.8
      swftophp cve/2018/8806/heap-use-after-free.swf

- CVE-2018-8964: [use after free][libming-130]

      guix shell libming-with-asan@0.4.8
      swftophp cve/2018/8964/heap-use-after-free.swf

## libtiff

- BZ#2633: [heap buffer overflow][maptools-2633]:

      guix shell libtiff-with-asan@4.0.7
      tiff2ps maptools/2633/heapoverflow.tiff

- CVE-2014-8128: [buffer overflow][maptools-2489]

      guix shell libtiff@4.0.3
      thumbnail cve/2014/8128/03_thumbnail.tiff /dev/null

- CVE-2016-3186: [buffer overflow][redhat-1319503]

      guix shell libtiff@4.0.6
      gif2tiff cve/2016/3186/crash.gif -

- CVE-2016-3623: [division by zero][maptools-2569]

      guix shell libtiff@4.0.6
      tar xvf $(guix build -S libtiff@4.0.6)\
        tiff-4.0.6/test/images/logluv-3c-16b.tiff
      rgb2ycbcr -h 0 tiff-4.0.6/test/images/logluv-3c-16b.tiff /dev/null
      rgb2ycbcr -v 0 tiff-4.0.6/test/images/logluv-3c-16b.tiff /dev/null

- CVE-2016-5314: [heap buffer overflow][maptools-2554]

      guix shell libtiff-with-asan@4.0.6
      rgb2ycbcr cve/2016/5314/oobw.tiff /dev/null

- CVE-2016-5321: [invalid read][maptools-2558]

      guix shell libtiff@4.0.6
      tiffcrop cve/2016/5321/ill-read.tiff /dev/null

- CVE-2016-9273: [heap buffer overflow][maptools-2587]

      guix shell libtiff-with-asan@4.0.6
      tiffsplit cve/2016/9273/test049.tiff

- CVE-2016-9532: [heap buffer overflow][maptools-2592]

      guix shell libtiff-with-asan@4.0.6
      tiffcrop cve/2016/9532/heap-buffer-overflow.tiff /dev/null

- CVE-2016-10092: [heap buffer overflow][maptools-2622]

      guix shell libtiff-with-asan@4.0.7
      tiffcrop -i cve/2016/10092/heapoverflow.tiff /dev/null

- CVE-2016-10093: [heap buffer overflow][maptools-2610]

      guix shell libtiff-with-asan@4.0.7
      tiffcp -i cve/2016/10093/heapoverflow.tiff /dev/null

- CVE-2016-10094: [heap buffer overflow][maptools-2640]

      guix shell libtiff-with-asan@4.0.7
      tiff2pdf cve/2016/10094/heapoverflow.tiff -o /dev/null

- CVE-2016-10266: [division by zero][maptools-2596]

      guix shell -e '(@@ (redacted bugs) libtiff-4.0.7)'
      tiffcp cve/2016/10266/fpe.tiff /dev/null

- CVE-2016-10267: [division by zero][maptools-2611]

      guix shell -e '(@@ (redacted bugs) libtiff-4.0.7)'
      tiffmedian cve/2016/10267/fpe.tiff /dev/null

- CVE-2016-10268: [heap buffer overflow][maptools-2598]

      guix shell libtiff-with-asan@4.0.7
      tiffcp -i cve/2016/10268/heapoverflow.tiff /dev/null

- CVE-2016-10271: [heap buffer overflow][maptools-2620]

      guix shell libtiff-with-asan@4.0.7
      tiffcrop -i cve/2016/10271/heapoverflow.tiff /dev/null

- CVE-2016-10272: [heap buffer overflow][maptools-2624]

      guix shell libtiff-with-asan@4.0.7
      tiffcrop -i cve/2016/10272/heapoverflow.tiff /dev/null

- CVE-2017-5225: [heap buffer overflow][maptools-2656]

      guix shell libtiff-with-asan@4.0.7
      tiffcp -p separate cve/2017/5225/2656.tiff /dev/null
      tiffcp -p contig cve/2017/5225/2657.tiff /dev/null

- CVE-2017-7595: [division by zero][maptools-2653]

      guix shell libtiff@4.0.7
      tiffcp -i cve/2017/7595/fpe.tiff /dev/null

- cve-2017-7599: [float cast overflow][maptools-2646]

      guix shell libtiff-with-ubsan-float-cast-overflow@4.0.7
      tiffcp -i cve/2017/7599/outside-short.tiff /dev/null

- cve-2017-7600: [float cast overflow][maptools-2647]

      guix shell libtiff-with-ubsan-float-cast-overflow@4.0.7
      tiffcp -i cve/2017/7600/outside-unsigned-char.tiff /dev/null

- CVE-2017-7601: [signed integer overflow][maptools-2648]

      guix shell libtiff-with-ubsan@4.0.7
      tiffcp -i cve/2017/7601/shift-long.tiff /dev/null

## libxml2

- CVE-2012-5134: [heap buffer overflow][chromium-40076524]

      guix shell libxml2-with-asan@2.9.0
      xmllint cve/2012/5134/bad.xml

- CVE-2016-1838: [heap buffer overflow][chromium-42452154]

      guix shell libxml2-with-asan@2.9.3
      xmllint cve/2016/1838/attachment_316158

- CVE-2016-1839: [heap buffer overflow][chromium-42452152]

      guix shell libxml2-with-asan@2.9.3
      xmllint --html cve/2016/1839/asan_heap-oob

- CVE-2017-5969: [null pointer derefence][oss-sec-20161105-3]

      guix shell libxml2@2.9.4
      xmllint --recover cve/2017/5969/crash-libxml2-recover.xml

## potrace

- CVE-2013-7437: [possible heap overflow][redhat-955808]

      guix shell -e '(@@ (redacted bugs) potrace-1.11)'
      potrace cve/2013/7437/1.bmp
      potrace cve/2013/7437/2.bmp

[chromium-40058947]: https://issues.chromium.org/issues/40058947
[chromium-40076524]: https://issues.chromium.org/issues/40076524
[chromium-42452152]: https://project-zero.issues.chromium.org/issues/42452152
[chromium-42452154]: https://project-zero.issues.chromium.org/issues/42452154
[gnu-19784]: https://debbugs.gnu.org/cgi/bugreport.cgi?bug=19784
[gnu-25003]: https://debbugs.gnu.org/cgi/bugreport.cgi?bug=25003
[gnu-25023]: https://debbugs.gnu.org/cgi/bugreport.cgi?bug=25023
[gnu-26545]: https://debbugs.gnu.org/cgi/bugreport.cgi?bug=26545
[jasper-22]: https://github.com/jasper-software/jasper/issues/22
[jasper-49]: https://github.com/jasper-software/jasper/issues/49
[jasper-67]: https://github.com/jasper-software/jasper/issues/67
[libarchive-717]: https://github.com/libarchive/libarchive/issues/717
[libjpeg-turbo-258]: https://github.com/libjpeg-turbo/libjpeg-turbo/issues/258
[libjpeg-turbo-305]: https://github.com/libjpeg-turbo/libjpeg-turbo/issues/305
[libming-128]: https://github.com/libming/libming/issues/128
[libming-130]: https://github.com/libming/libming/issues/130
[maptools-2489]: http://bugzilla.maptools.org/show_bug.cgi?id=2489
[maptools-2554]: http://bugzilla.maptools.org/show_bug.cgi?id=2554
[maptools-2558]: http://bugzilla.maptools.org/show_bug.cgi?id=2558
[maptools-2569]: http://bugzilla.maptools.org/show_bug.cgi?id=2569
[maptools-2587]: http://bugzilla.maptools.org/show_bug.cgi?id=2587
[maptools-2592]: http://bugzilla.maptools.org/show_bug.cgi?id=2592
[maptools-2596]: http://bugzilla.maptools.org/show_bug.cgi?id=2596
[maptools-2598]: http://bugzilla.maptools.org/show_bug.cgi?id=2598
[maptools-2610]: http://bugzilla.maptools.org/show_bug.cgi?id=2610
[maptools-2611]: http://bugzilla.maptools.org/show_bug.cgi?id=2611
[maptools-2620]: http://bugzilla.maptools.org/show_bug.cgi?id=2620
[maptools-2622]: http://bugzilla.maptools.org/show_bug.cgi?id=2622
[maptools-2624]: http://bugzilla.maptools.org/show_bug.cgi?id=2624
[maptools-2633]: http://bugzilla.maptools.org/show_bug.cgi?id=2633
[maptools-2640]: http://bugzilla.maptools.org/show_bug.cgi?id=2640
[maptools-2646]: http://bugzilla.maptools.org/show_bug.cgi?id=2646
[maptools-2647]: http://bugzilla.maptools.org/show_bug.cgi?id=2647
[maptools-2648]: http://bugzilla.maptools.org/show_bug.cgi?id=2648
[maptools-2653]: http://bugzilla.maptools.org/show_bug.cgi?id=2653
[maptools-2656]: http://bugzilla.maptools.org/show_bug.cgi?id=2656
[mozjpeg-268]: https://github.com/mozilla/mozjpeg/issues/268
[oss-sec-20161105-3]: https://www.openwall.com/lists/oss-security/2016/11/05/3
[oss-sec-20161110-9]: https://www.openwall.com/lists/oss-security/2016/11/10/9
[redhat-955808]: https://bugzilla.redhat.com/show_bug.cgi?id=955808
[redhat-1319503]: https://bugzilla.redhat.com/show_bug.cgi?id=1319503
[sourceware-21137]: https://sourceware.org/bugzilla/show_bug.cgi?id=21137
[sourceware-22148]: https://sourceware.org/bugzilla/show_bug.cgi?id=22148
[sourceware-22186]: https://sourceware.org/bugzilla/show_bug.cgi?id=22186
[sourceware-22202]: https://sourceware.org/bugzilla/show_bug.cgi?id=22202
[sourceware-23064]: https://sourceware.org/bugzilla/show_bug.cgi?id=23064
[sourceware-24243]: https://sourceware.org/bugzilla/show_bug.cgi?id=24243
