#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include <assert.h>
#include <string.h>

/*******************
�����ַ�ջ��ʵ�ֲ���
*******************/
#define STRING_STACK_INIT_SIZE 50
/************************
�̶����ȵ�����ʵ���ַ�ջ
************************/
typedef struct StringStack{
    char* data[STRING_STACK_INIT_SIZE];
    int topElement;
    //int stackSize;
}StringStack;

void InitStringStack(StringStack *s);
void FreeStringStack(StringStack *s);
bool EmptyStringStack(StringStack *s);
void PushStringStack(StringStack *s,char* e);
void PopStringStack(StringStack *s);
char* TopStringStack(StringStack *s);


/*******************
���ڽڵ�ջ��ʵ�ֲ���
*******************/

typedef struct Node
{
    char* value;
    struct Node* left;
    struct Node* right;
}Node;

#define NODE_STACK_INIT_SIZE 50
/************************
�̶���������ʵ�ֽڵ�ջ
����Ԫ����ָ��ڵ��ָ��
************************/
typedef struct NodeStack{
    Node* data[NODE_STACK_INIT_SIZE];
    int topElement;
    //int stackSize;
}NodeStack;

void InitNodeStack(NodeStack *s);
void FreeNodeStack(NodeStack *s);
bool EmptyNodeStack(NodeStack *s);
void PushNodeStack(NodeStack *s,Node* e);
void PopNodeStack(NodeStack *s);
Node* TopNodeStack(NodeStack *s);

/********
���Բ���
********/
int nextAttribute(char* policy,char* word,int index);
Node* generateTree(char* policy);
void preSearch(Node* root);
bool match(Node* root,const char* attrs);
void free_tree(Node* root);
