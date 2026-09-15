users = {
    "red_team_lead": {
        "role": "red_team",
        "clearance": 4,
        "department": "RedTeam",
        "active": True,
    },
    "blue_team_analyst": {
        "role": "blue_team",
        "clearance": 3,
        "department": "Blue Team",
        "active": True,
    },
    "purple_team_coord": {
        "role": "purple_team",
        "clearance": 3,
        "department": "Purple Team",
        "active": True,
    },
    "student_intern": {
        "role": "student",
        "clearance": 1,
        "department": "Academia",
        "active": True,
    },
    "retired_expert": {
        "role": "retired",
        "clearance": 2,
        "department": "Emeritus",
        "active": False,
    },
}
resources = [
    ("attack_scenarios", 4),
    ("defense_playbooks", 3),
    ("exercise_plans", 3),
    ("research_papers", 1),
    ("exploit_tools", 4),
    ("student_resources", 1),
    ("simulation_results", 3),
    ("red_team_tools", 4),
    ("blue_team_reports", 3),
    ("public_research", 1),
]
security_levels = ("Academic", "Operational", "Tactical", "Strategic")
blocked_users = {"retired_expert", "academic_violator", "leaked_account"}


def main():
    for resource, levels in resources:
        print(resource, security_levels[levels - 1])

    print("\n")

    for user in users:
        for resource, levels in resources:
            if user in blocked_users:
                print(f"user=[{user}] resource=[{resource}] -> DENY (User is blocked)")
            elif users[user]["active"] == False:
                print(f"user=[{user}] resource=[{resource}] -> DENY (Account inactive)")
            elif users[user]["clearance"] >= levels:
                print(f"user=[{user}] resource=[{resource}] -> ALLOW")
            elif users[user]["clearance"] < levels:
                print(
                    f"user=[{user}] resource=[{resource}] -> DENY (Insufficient clearance)"
                )
            else:
                print(f"user=[{user}] resource=[{resource}] -> DENY (User not found)")


if __name__ == "__main__":
    main()
