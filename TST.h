#ifndef TST_h
#define TST_h

#include <stdlib.h>
#include <string.h>
#include "SLL.h"

/*
 * TST node structure.
 */
typedef struct TSTNode
{
  char c;     /* charcter in the node */
  void *data; /* data to store with charcter */
  int8_t isEndOfAString;
  struct TSTNode *left, *mid, *right; /* pointers for TST */
} TSTNode;

/*
 * TST info structure.
 */
typedef struct TSTInfo
{
  int size;               /* number of key value pairs in the TST */
  SLL *memory_allocations; /* list of allocated memory of nodes */
} TSTInfo;

/* TST Type*/
typedef TSTNode TST;

/*
 * TST initializer.
 * return value: the root node of the TST.
 */
static TST *TST_init()
{
  /* TST info keeper */
  TSTInfo *info = (TSTInfo *)malloc(sizeof(TSTInfo));
  info->size = 0;
  info->memory_allocations = SLL_init();

  /* TST creation */
  TST *node = (TST *)malloc(sizeof(TST));
  node->c = 0;
  node->data = info;
  node->isEndOfAString = 0;
  node->left = NULL;
  node->mid = NULL;
  node->right = NULL;

  return node;
}

/*
 * please see TST_get
 */
static TSTNode *_TST_get_(TSTNode *node, char *key, int i)
{
  size_t key_len;
  if (!node || !key || (key_len = strlen(key)) < 1 || i < 0)
    return NULL;
  char c = key[i];
  if (c < node->c)
    return _TST_get_(node->left, key, i);
  else if (c > node->c)
    return _TST_get_(node->right, key, i);
  else
  {
    if (i == key_len - 1)
      return node;
    else
      return _TST_get_(node->mid, key, i + 1);
  }
}

/*
 * get the data data of a given key from a TST.
 * tst: target TST.
 * key: target key.
 * return value: pointer to the data on success, 0 (NULL) otherwise.
 */
static void *TST_get(TST *tst, char *key)
{
  if (!tst || !key || strlen(key) < 1)
    return NULL;
  TSTNode *node = _TST_get_(tst, key, 0);
  if (!node || !(node->isEndOfAString))
    return NULL;
  return node->data;
}

/*
 * Verify if a key exists in the TST
 * tst: target TST.
 * key: target key.
 * return value: 1 on success, 0 otherwise.
 */
static int TST_contains(TST *tst, char *key)
{
  if (!tst || !key)
    return 0;
  return !TST_get(tst, key) ? 0 : 1;
}

/*
 * please see TST_put
 */
static TSTNode *_TST_put_(TST *tst, TSTNode *node, char *key, void *data, int i)
{
  size_t key_len;
  if (!key || (key_len = strlen(key)) < 1 || i < 0)
  {
    return NULL;
  }

  char c = key[i];
  if (!node)
  {
    node = (TSTNode *)malloc(sizeof(TSTNode));
    node->c = c;
    node->data = NULL;
    node->isEndOfAString = 0;
    node->left = NULL;
    node->mid = NULL;
    node->right = NULL;

    /* save the allocation into list */
    TSTInfo *info = (TSTInfo *)tst->data;
    SLL_insert(info->memory_allocations, node);
  }
  if (c < node->c)
    node->left = _TST_put_(tst, node->left, key, data, i);
  else if (c > node->c)
    node->right = _TST_put_(tst, node->right, key, data, i);
  else
  {
    if (i == key_len - 1)
    {
      node->data = data;
      node->isEndOfAString = 1;
    }
    else
      node->mid = _TST_put_(tst, node->mid, key, data, i + 1);
  }
  return node;
}

/*
 * Add a key data pair to a TST.
 * tst: target TST.
 * key: target key.
 * data: target data.
 * return value: 1 on success, 0 otherwise.
 */
static int TST_put(TST *tst, char *key, void *data)
{
  if (!tst || !key)
    return 0;

  if (!TST_contains(tst, key))
  {
    TSTInfo *info = (TSTInfo *)tst->data;
    info->size++;
  }
  return _TST_put_(tst, tst, key, data, 0) ? 1 : 0;
}

/*
 * free a TST.
 * tst: target TST.
 */
static void TST_free(TST *tst)
{
  TSTInfo *info = (TSTInfo *)tst->data;

  /* free the allocated TST nodes */
  SLLNode *iter = info->memory_allocations->next;
  while (iter)
  {
    SLLNode *next = iter->next;
    free(iter->data);
    iter = next;
  }

  /* free the TST info */
  SLL_free(info->memory_allocations);
  free(info);
  info = NULL;
  free(tst);
  tst = NULL;
}

#endif
