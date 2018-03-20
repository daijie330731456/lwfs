/*
 *tree.c
 *created on: 2017-5-12
      Author: dj
 */
#include "tree.h"
/*******************************************
c�汾�Ĳ��Դ����ļ��������������֣�
�ַ�ջ��ʵ�֡��ڵ�ջ��ʵ�֡����Բ��ֵ�ʵ��
*******************************************/


/*******************
�����ַ�ջ��ʵ�ֲ���
*******************/

/***********
��ʼ���ַ�ջ
************/
void InitStringStack(StringStack *s)
{
    if(s==NULL)
        return;
    s->topElement=-1;
    return;
}
/***************
�ÿ��ַ�ջ��ָ��
***************/
void FreeStringStack(StringStack *s)
{
    if(s==NULL)
        return;
    s=NULL;
}
/******************
�ж��ַ�ջ�Ƿ�Ϊ��
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
�ַ�ջ��ջ
***********/
void PushStringStack(StringStack *s,char* e)
{
    s->topElement+=1;
    (s->data)[s->topElement]=e;

}
/*********
�ַ�ջ��ջ
**********/
void PopStringStack(StringStack *s)
{
    if(EmptyStringStack(s))
        return;
    s->topElement-=1;
}
/******************
�����ַ�ջջ��Ԫ��
******************/
char* TopStringStack(StringStack *s)
{
    if(EmptyStringStack(s))
        return "error";
    return (s->data)[s->topElement];
}


/*******************
���ڽڵ�ջ��ʵ�ֲ���
*******************/

/***********
��ʼ���ڵ�ջ
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
�ÿսڵ�ջָ��
**************/
void FreeNodeStack(NodeStack *s)
{
    if(s==NULL)
        return;
    s=NULL;
}
/*******
�ж�ջ��
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
�ڵ�ջ��ջ
**********/
void PushNodeStack(NodeStack *s,Node* e)
{
    s->topElement+=1;
    (s->data)[s->topElement]=e;
}
/**********
�ڵ�ջ��ջ
**********/
void PopNodeStack(NodeStack *s)
{
    if(EmptyNodeStack(s))
        return;
    s->topElement-=1;
}
/***********
����ջ���ڵ�
************/
Node* TopNodeStack(NodeStack *s)
{

    return (s->data)[s->topElement];
}


/********
���Բ���
********/

/****************************************************
���ã����÷��ʿ��Ʋ��ԣ��Լ���ǰ����������һ������
���룺
    policy:���ʿ��Ʋ��ԣ����磺 "((A OR BC)AND(E OR FG))AND((H AND IJ)OR(K OR MN))"
    word:  ���������һ�����ʣ����������Ӵ�Ҳ����������ֵ��
    index����ǰ�������±�
�����
    ������һ�α������±�
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
���ã����÷��ʿ��Ʋ��ԣ�����һ�÷��ʿ��ƵĶ�����
���룺
    policy:���ʿ��Ʋ��ԣ����磺 "((A OR BC)AND(E OR FG))AND((H AND IJ)OR(K OR MN))"
�����
    �������ɶ������ĸ��ڵ��ַ
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
�������������
�������������Ƿ񹹽��ɹ�
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
 ����: match���������ж�ĳ�û������Լ����Ƿ�������ʿ�����
 ���룺
 * 		root: ���ʿ��ƶ������ĸ��ڵ�
 *		attrs�� �û������Լ�����ʽ���� "User IT_Department Manager"(����������
                ֮�����ÿո���߶��Ÿ���)
 �����
 *	     ������������ �򷵻� 1
 *		 ���򷵻� 0
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
            //����ֱ�ӿ��ַ������Ƿ���������ַ��Ӵ�����Ϊһ�����Կ��ܰ�����һ�����ԣ����磺
            //woman�����оͰ�����man��,���һ�������ԡ�student woman��,�ǿ����ѳ���man���Ӵ���
            //�������ҵ��Ӵ�����Ҫ��ǰ���ǲ������Էָ��ţ��ո���Ƕ���


            //��β���ߺ�һ���ַ�Ϊ�ո�����Ƕ��ű�ʾ����ֵ�ķָ���
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
���չ�����������ʱ��malloc�Ŀռ�
�����ڵ��valueֵ��wordҲ��malloc�����ģ�
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
