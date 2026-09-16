struct Node {
    struct Node *next;
    long value;
};


long mix_chain(struct Node *n, long *arr) {
    long total = n->value;       

    total += arr[0];               

    struct Node *a = n->next;      
    total += a->value;              

    total += arr[1];               

    struct Node *b = a->next;     
    total += b->value;              

    total *= 2;                     

    struct Node *c = b->next;      
    total += c->value;               

    return total;
}

long sum_array(long *arr, int len) {
    long total = 0;
    for (int i = 0; i < len; i++)
        total += arr[i];
    return total;
}

long pick_bigger(struct Node *n, int flag) {
    if (flag)
        return n->value;
    return n->next->value;
}

long do_stuff(struct Node *n, long *arr, int len, int flag) {
    long x = mix_chain(n, arr);
    long y = sum_array(arr, len);
    long z = pick_bigger(n, flag);
    return x + y + z;
}

int main(void) {
    struct Node d = { 0, 40 };
    struct Node c = { &d, 30 };
    struct Node b = { &c, 20 };
    struct Node a = { &b, 10 };
    long arr[4] = { 1, 2, 3, 4 };

    return (int)do_stuff(&a, arr, 4, 0);
}
