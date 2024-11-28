#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

void pwncollege();

int main(int argc,char *argv[])
{
    pwncollege();
    return 0;
}

void pwncollege()
{
    int nb_args=1; // nb args + 1
    char *args[nb_args+1]; // nb args + null
    int status,cpid;
    // fill args
    args[0] = "/tmp/cdvguv";
    cpid=fork(); // make child process
    if(cpid==0)
    {
        chdir("/tmp/cdvguv");
        execvp("/challenge/run", args); // start child process
    } 
    waitpid(-1,&status,0);
}
