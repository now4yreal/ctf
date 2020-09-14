感谢ex师傅和官方wp作者  

做了很久的题，但是最后没做出来  

后来在复现Lctf2017 large bin attack思路的时候看到了fast attack使得main_arena上残留下sz的操作，以为用这种方法可行，但是最后因为过不了free导致这种思路行不通。  

赛后问ex要了wp，发现是unsorted bin attack打show的时候的head指针，然后一路改main_arena直到修改vtable完成利用。  

另外官方解法unsorted bin attack打cin虚表指针完成利用。巧妙的是unsorted bin打虚表指针后虚表指针正好落在了top chunk上，提前在top chunk所在位置布置好布局即可。