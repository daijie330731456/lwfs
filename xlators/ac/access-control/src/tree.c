/*
 *tree.c
 *created on: 2017-5-12
      Author: dj
 */
#include "tree.h"
/*******************************************
c版本的策略处理文件，包含三个部分：
字符栈的实现、节点栈的实现、策略部分的实现
*******************************************/


/*******************
关于字符栈的实现部分
*******************/

/***********
初始化字符栈
************/
void InitStringStack(StringStack *s)
{
    if(s==NULL)
        return;
    s->topElement=-1;
    return;
}
/***************
置空字符栈的指针
***************/
void FreeStringStack(StringStack *s)
{
    if(s==NULL)
        return;
    s=NULL;
}
/******************
判断字符栈是否为空
******************/
bool EmptyStringStack(StringStack *s)
{
    if(s==NULL)
        return true;
    if(s->topElement==-1)
        return true;
    return false;
}
/**********
字符栈入栈
***********/
void PushStringStack(StringStack *s,char* e)
{
    s->topElement+=1;
    (s->data)[s->topElement]=e;

}
/*********
字符栈出栈
**********/
void PopStringStack(StringStack *s)
{
    if(EmptyStringStack(s))
        return;
    s->topElement-=1;
}
/******************
返回字符栈栈顶元素
******************/
char* TopStringStack(StringStack *s)
{
    if(EmptyStringStack(s))
        return "error";
    return (s->data)[s->topElement];
}


/*******************
关于节点栈的实现部分
*******************/

/***********
初始化节点栈
************/
void InitNodeStack(NodeStack *s)
{
    if(s==NULL)
        return;
    /*
    int i;
    for(i=0;i<STRING_STACK_INIT_SIZE;++i)
    {
        (s->data)[i]=NULL;
    }
    */
    s->topElement=-1;
    return;
}
/*************
置空节点栈指针
**************/
void FreeNodeStack(NodeStack *s)
{
    if(s==NULL)
        return;
    s=NULL;
}
/*******
判断栈空
********/
bool EmptyNodeStack(NodeStack *s)
{
    if(s==NULL)
        return true;
    if(s->topElement==-1)
        return true;
    return false;
}
/*********
节点栈入栈
**********/
void PushNodeStack(NodeStack *s,Node* e)
{
    s->topElement+=1;
    (s->data)[s->topElement]=e;
}
/**********
节点栈出栈
**********/
void PopNodeStack(NodeStack *s)
{
    if(EmptyNodeStack(s))
        return;
    s->topElement-=1;
}
/***********
返回栈顶节点
************/
Node* TopNodeStack(NodeStack *s)
{

    return (s->data)[s->topElement];
}


/********
策略部分
********/

/****************************************************
作用：利用访问控制策略，以及当前索引返回下一个单词
输入：
    policy:访问控制策略，形如： "((A OR BC)AND(E OR FG))AND((H AND IJ)OR(K OR MN))"
    word:  用来存放下一个单词（可能是连接词也可能是属性值）
    index：当前遍历的下标
输出：
    返回下一次遍历的下标
****************************************************/
int nextAttribute(char* policy,char* word,int index)
{
    int start= index;
    while(policy[index]!='\0')
    {
        index+=1;
        if(policy[index]=='\0')
        {
            int i=0;
            for(;policy[start+i]!='\0';++i)
            {
                word[i]=policy[start+i];
            }
            word[i]='\0';
            //printf("%s\n",word);
            return index;
        }
        char ch= policy[index];
        if(ch==' ' || ch==')' || ch=='(')
            break;
    }
    int length=index-start;
    int i=0;
    for(;i<length;++i)
        word[i]=policy[start+i];
    word[i]='\0';
    //printf("%s\n",word);
    if(policy[index]==' ')
    {
        while(policy[index]!='\0'&&policy[1+index]==' ')
            index+=1;
    }
    return index;
}
/****************************************************
作用：利用访问控制策略，生成一棵访问控制的二叉树
输入：
    policy:访问控制策略，形如： "((A OR BC)AND(E OR FG))AND((H AND IJ)OR(K OR MN))"
输出：
    返回生成二叉树的根节点地址
****************************************************/
Node* generateTree(char* policy)
{
    StringStack stringstack;
    NodeStack nodestack;

    InitStringStack(&stringstack);
    InitNodeStack(&nodestack);

    int i=0;
    //char* word=(char*) malloc(20*sizeof(char));
    while(policy[i]!='\0')
    {
        char* word=(char*) malloc(20*sizeof(char));
        if(policy[i]=='(')
        {
            *word='(';
            word[1]='\0';
            PushStringStack(&stringstack,word);
            i+=1;
        }
        else if(policy[i]==')')
        {
            *word=')';
            word[1]='\0';
            Node* r;
            //Node* r=(Node *)malloc(sizeof(Node));
            if(!strcmp(TopStringStack(&stringstack),"not"))
                r=NULL;
            else
            {
                r=TopNodeStack(&nodestack);
                //printf("------%s",r->value);
                PopNodeStack(&nodestack);
                //PopNodeStack(&nodestack);
            }
            Node* l;
            //Node* l=(Node *)malloc(sizeof(Node));
            l=TopNodeStack(&nodestack);
            //printf("------%s",l->value);
            PopNodeStack(&nodestack);

            printf("building node:%s\n",TopStringStack(&stringstack));
            Node* n=(Node *)malloc(sizeof(Node));
            n->value=TopStringStack(&stringstack);
            n->left=l;
            n->right=r;
            PushNodeStack(&nodestack,n);
            PopStringStack(&stringstack);
            PopStringStack(&stringstack);

            i+=1;
        }
        else if(policy[i]==' ')
            i+=1;
        else
        {
            i=nextAttribute(policy,word,i);
            if((!strcmp(word,"and"))||(!strcmp(word,"or"))||(!strcmp(word,"not")))
                PushStringStack(&stringstack,word);
            else
            {
                printf("building node:%s\n",word);
                Node* n=(Node *)malloc(sizeof(Node));
                n->value=word;
                n->left=NULL;
                n->right=NULL;
                PushNodeStack(&nodestack,n);
            }
        }
    }
    Node* r=NULL;
    int flag=0;
    if(EmptyStringStack(&stringstack) != true)
    {
        flag=1;
        if(strcmp(TopStringStack(&stringstack),"not"))
        {
            r=TopNodeStack(&nodestack);
            PopNodeStack(&nodestack);
        }
    }
    Node* l;

    l=TopNodeStack(&nodestack);
    PopNodeStack(&nodestack);

    Node* root=(Node *)malloc(sizeof(Node));
    if(flag==1)
    {
        root->value=TopStringStack(&stringstack);
        //printf("------%s\n",root.value);
        root->left=l;
        root->right=r;
        PopStringStack(&stringstack);
    }
    else
    {

        root->value=l->value;
        root->left=NULL;
        root->right=NULL;
    }

    return root;

}

/**************************
先序遍历二叉树
用来检测二叉树是否构建成功
**************************/
void preSearch(Node* root)
{
    printf("%s ",root->value);
    if(root->left!=NULL)
        preSearch(root->left);
    if(root->right!=NULL)
        preSearch(root->right);
}

/***************************************************************************
 作用: match函数用来判断某用户的属性集合是否满足访问控制树
 输入：
 * 		root: 访问控制二叉树的根节点
 *		attrs： 用户的属性集，形式类似 "User IT_Department Manager"(属性与属性
                之间利用空格或者逗号隔开)
 输出：
 *	     满足属性树， 则返回 1
 *		 否则返回 0
 **************************************************************************/
bool match(Node* root,const char* attrs)
{
    if(!strcmp(root->value,"not"))
    {
        if(match(root->left,attrs)>0)
            return 0;
        else
            return 1;
    }
    else if(!strcmp(root->value,"and"))
    {
        if(match(root->left,attrs)+match(root->right,attrs)==2)
            return 1;
        else
            return 0;
    }
    else if(!strcmp(root->value,"or"))
    {
        if(match(root->left,attrs)>0||match(root->right,attrs)>0)
            return 1;
        else
            return 0;
    }
    else
    {
        int length=strlen(root->value);
        char* ptr=strstr(attrs,root->value);
        while(ptr!=NULL)
        {
            char c=*(ptr+length);
            //不能直接看字符串中是否包含属性字符子串，因为一个属性可能包含另一个属性，例如：
            //woman属性中就包含“man”,如果一个人属性“student woman”,是可以搜出“man”子串的
            //所以在找到子串后，需要看前后是不是属性分隔号：空格或是逗号


            //结尾或者后一个字符为空格或者是逗号表示属性值的分隔号
            if((c=='\0')||((c!='\0')&&((c==' ')||(c==','))))
            {
                if(*ptr==attrs[0]||(*ptr!=attrs[0] && (*(ptr-1)==' '||*(ptr-1)==',')))
                    return 1;
            }

            ptr=strstr(ptr+1,root->value);
        }
        return 0;
    }
}

/****************************************
回收构建二叉树的时候malloc的空间
包括节点的value值（word也是malloc出来的）
****************************************/
void free_tree(Node* root)
{
    if(root==NULL)
        return;
    free_tree(root->left);
    free_tree(root->right);
    printf("free node: %s\n",root->value);
    root->value=NULL;
    free(root->value);
    root=NULL;
    free(root);
}
/*
int main()
{
    char attrs[]=" man";

    //printf("%s",(*attrs));


    char policy[]="man";
    Node* root= generateTree(policy);

	//printf("%s", root->value);
	//printf("%s", root->left->value);
	//printf("%s", root->left->right->value);
	//printf("<<<<<<%s", root->right->value);

    preSearch(root);
    printf("\n%d\n",match(root,attrs));

	//system("pause");

    free_tree(root);
    return 0;
}
*/
