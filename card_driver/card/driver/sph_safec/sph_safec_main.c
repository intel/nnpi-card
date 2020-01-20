#include <linux/module.h>
#include <linux/init.h>

static int __init my_init(void)
{
	return 0;
}

static void __exit my_exit(void)
{
    return;
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SpringHill Card safe functions.");
MODULE_AUTHOR("Intel Corporation");