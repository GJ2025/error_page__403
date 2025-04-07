#include<stdio.h>
#include<stdlib.h>
#include <fcntl.h>   // open() 函数定义
#include <unistd.h>  // close() 函数定义

int main() {
    const char *filename = "/proc/simple_int";  // 示例文件（如 /proc 下的文件）
    int fd;
    int abc = 0;

    // 使用 O_RDONLY 标志打开文件（只读模式）
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open failed");  // 输出错误原因（如文件不存在或权限不足）
        return 1;
    }

    // 在此处进行读取操作（使用 read() 函数）...

	read(fd, &abc, sizeof(abc));

	printf("abc: %d\n", abc);

    close(fd);  // 必须关闭文件描述符
    return 0;
}

