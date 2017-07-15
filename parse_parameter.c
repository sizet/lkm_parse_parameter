// ©.
// https://github.com/sizet/lkm_parse_parameter

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>




#define FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DMSG(msg_fmt, msg_args...) \
    printk(KERN_INFO "%s(%04u): " msg_fmt "\n", FILE_NAME, __LINE__, ##msg_args)




// 每個參數的分隔符號.
#define PARAMETER_DATA_SPLIT_KEY  ' '
// 參數名稱和參數資料的分隔符號.
#define PARAMETER_VALUE_SPLIT_KEY '='


// 紀錄參數資料的結構.
struct parameter_record_t
{
    // 參數的名稱.
    char *data_name;
    // 指向參數的資料的位址.
    char *data_value;
    // 參數是否必須存在, 0:否, 1:是.
    unsigned int is_must;
};

// 參數表 (編號).
enum PARA_RECORD_INDEX_LIST
{
    PR_SSID_INDEX = 0,
    PR_IP_ADDR_INDEX,
    PR_NAME_INDEX,
    PR_MAC_ADDR_INDEX
};
// 參數表 (名稱).
struct parameter_record_t para_record_list[] =
{
    {"ssid",     NULL, 1},
    {"ip-addr",  NULL, 1},
    {"name",     NULL, 0},
    {"mac_addr", NULL, 1},
    {NULL, NULL, 0}
};




static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos);

static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos);

static char *node_name = "parse_parameter";
static struct proc_dir_entry *node_entry;
static struct file_operations node_fops =
{
    .read  = node_read,
    .write = node_write,
};




static int split_parameter(
    char **para_con_buf,
    size_t *para_len_buf,
    char **data_name_buf,
    char **data_value_buf)
{
    char *pcon;
    size_t plen, idx1, idx2, more_para = 0;


    pcon = *para_con_buf;
    plen = *para_len_buf;

    // 跳過開頭的參數分隔符號 (PARAMETER_DATA_SPLIT_KEY).
    // 例如 :
    // "  ssid=abcd ip-addr=192.168.1.2"
    // 跳過 "  ".
    for(idx1 = 0; idx1 < plen; idx1++)
        if(pcon[idx1] != PARAMETER_DATA_SPLIT_KEY)
            break;
    if(idx1 > 0)
    {
        pcon += idx1;
        plen -= idx1;
    }

    // 表示沒有其他參數.
    if(plen == 0)
        return 0;

    // 找到參數分隔符號 (PARAMETER_DATA_SPLIT_KEY), 分離參數.
    // 例如 :
    // "ssid=abcd ip-addr=192.168.1.2"
    // 找到 " ".
    for(idx1 = 0; idx1 < plen; idx1++)
        if(pcon[idx1] == PARAMETER_DATA_SPLIT_KEY)
        {
            pcon[idx1] = '\0';
            more_para = 1;
            break;
        }

    // 找到參數名稱和參數資料的分隔符號 (PARAMETER_VALUE_SPLIT_KEY), 分離參數名稱和參數資料.
    // 例如 :
    // "ssid=abcd"
    // 找到 "=".
    for(idx2 = 0; idx2 < idx1; idx2++)
        if(pcon[idx2] == PARAMETER_VALUE_SPLIT_KEY)
        {
            pcon[idx2] = '\0';
            break;
        }

    // 紀錄參數名稱.
    *data_name_buf = pcon;

    // 紀錄參數資料.
    // 例如 :
    // "ssid=abcd"
    // idx1 = 9, idx2 = 4, 有參數資料.
    // "ssid"
    // idx1 = 4, idx2 = 4, 沒有參數資料.
    *data_value_buf = idx2 < idx1 ? pcon + idx2 + 1 : NULL;

    // 移動參數內容, 跳過這次處理的參數.
    // 調整參數內容長度, 減去這次處理的參數.
    idx1 += more_para;
    *para_con_buf = pcon + idx1;
    *para_len_buf = plen - idx1;

    return 1;
}

static int parse_parameter(
    char *para_con,
    size_t para_len,
    struct parameter_record_t *target_list)
{
    struct parameter_record_t *each_pr;
    char *tmp_name, *tmp_value;


    // 初始化.
    for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
        each_pr->data_value = NULL;

    while(1)
    {
        // 分離每個參數.
        if(split_parameter(&para_con, &para_len, &tmp_name, &tmp_value) == 0)
            break;
        DMSG("each [%s][%s]", tmp_name, tmp_value);

        for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
            if(strcmp(each_pr->data_name, tmp_name) == 0)
            {
                if(tmp_value == NULL)
                {
                    DMSG("miss value [%s]", each_pr->data_name);
                    return -1;
                }

                if(each_pr->data_value != NULL)
                {
                    DMSG("duplic data [%s]", each_pr->data_name);
                    return -1;
                }

                each_pr->data_value = tmp_value;
                break;
            }

        if(each_pr->data_name == NULL)
        {
            DMSG("unknown parameter [%s]", tmp_name);
            return -1;
        }
    }

    for(each_pr = target_list; each_pr->data_name != NULL; each_pr++)
        if(each_pr->data_value == NULL)
            if(each_pr->is_must != 0)
            {
                DMSG("miss data [%s]", each_pr->data_name);
                return -1;
            }

    return 0;
}

static int process_parameter(
    char *para_con,
    size_t para_len)
{
    struct parameter_record_t *each_pr;


    if(parse_parameter(para_con, para_len, para_record_list) < 0)
    {
        DMSG("call parse_parameter() fail");
        return -1;
    }

    each_pr = para_record_list + PR_SSID_INDEX;
    DMSG("%s = %s", each_pr->data_name, each_pr->data_value);

    each_pr = para_record_list + PR_IP_ADDR_INDEX;
    DMSG("%s = %s", each_pr->data_name, each_pr->data_value);

    each_pr = para_record_list + PR_NAME_INDEX;
    DMSG("%s = %s", each_pr->data_name, each_pr->data_value);

    each_pr = para_record_list + PR_MAC_ADDR_INDEX;
    DMSG("%s = %s", each_pr->data_name, each_pr->data_value);

    return 0;
}

static ssize_t node_read(
    struct file *file,
    char __user *buffer,
    size_t count,
    loff_t *pos)
{
    DMSG("%s <parameter>", node_name);
    DMSG("  ex : ssid=public-access ip-addr=192.168.12.34 name=local mac_addr=001122334455");

    return 0;
}

static ssize_t node_write(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *pos)
{
    char read_buf[256];
    size_t rlen = sizeof(read_buf) - 1;


    memset(read_buf, 0, sizeof(read_buf));
    rlen = count >= rlen ? rlen : count;
    copy_from_user(read_buf, buffer, rlen);
    if(rlen > 0)
        if(read_buf[rlen - 1] == '\n')
        {
            rlen--;
            read_buf[rlen] = '\0';
        }

    if(process_parameter(read_buf, rlen) < 0)
    {
        DMSG("call process_parameter() fail");
    }

    return count;
}

static int __init main_init(
    void)
{
    if((node_entry = proc_create(node_name, S_IFREG | S_IRUGO | S_IWUGO, NULL, &node_fops)) == NULL)
    {
        DMSG("call proc_create(%s) fail", node_name);
        return 0;
    }

    return 0;
}

static void __exit main_exit(
    void)
{
    remove_proc_entry(node_name, NULL);

    return;
}

module_init(main_init);
module_exit(main_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Che-Wei Hsu");
MODULE_DESCRIPTION("Parse Parameter");
