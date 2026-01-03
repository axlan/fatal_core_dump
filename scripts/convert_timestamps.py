import sys
import os
import datetime


def main():
    file_path = 'site/airlock_ctrl.log'

    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    updated_lines = []

    target_visit_start = datetime.datetime(2216, 5, 3, 14, 49, 7)
    offset = target_visit_start - datetime.datetime.fromtimestamp(62738937)

    VISIT_1_START_MS = 62738949765
    VISIT_2_START_MS = 62739588222
    VISIT_3_START_MS = 62740542569
    visit_count = 0

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Split on the first whitespace to isolate the timestamp
                parts = line.split(maxsplit=1)

                # Check if the first part is a valid digit (timestamp)
                if parts and parts[0].isdigit():
                    timestamp_ms = int(parts[0])

                    if visit_count == 0 and timestamp_ms == VISIT_1_START_MS:
                        offset += datetime.timedelta(days=6.9)
                        visit_count += 1
                    elif visit_count == 1 and timestamp_ms == VISIT_2_START_MS:
                        offset += datetime.timedelta(days=1.1)
                        visit_count += 1
                    elif visit_count == 2 and timestamp_ms == VISIT_3_START_MS:
                        offset += datetime.timedelta(days=13.7)
                        visit_count += 1


                    dt_object = datetime.datetime.fromtimestamp(timestamp_ms / 1000.0) + offset
                    dt_str = dt_object.strftime('%Y-%m-%d_%H:%M:%S')

                    rest_of_line = parts[1] if len(parts) > 1 else ""
                    updated_lines.append(f"{dt_str} {rest_of_line}")
                else:
                    updated_lines.append(line)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(updated_lines)
        print(f"Successfully processed '{file_path}'.")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
