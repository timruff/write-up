#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
void pwncollege();
int main(int argc, int *argv[]){
    int pid;
    int pstat;
    switch(pid=fork())
    {
        case 0:
           pwncollege();
    }
    waitpid(pid, (int*)&pstat,0); // wait process
    return 0;
}

void pwncollege(){
    execl("/challenge/run","run",(char *)NULL);
}
